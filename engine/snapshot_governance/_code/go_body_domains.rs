//! Conservative result domains for exact, admitted native Go scalar bodies.

use serde::Serialize;

use crate::information_flow::{NativeScalarFlowObservation, observe_lowered_native_scalar_flow};

use crate::program_semantics::go_observation::GoNativeBodyObservation;
use crate::program_semantics::native_body::{NativeScalar, NativeScalarBody};
use crate::semantic_analysis::{SemanticDomain, infer_native_scalar_output};

/// Exact original-source Go body observation with independently derived domains.
///
/// Domains bound the result of the admitted scalar statements under the
/// selected input domain. They confer no runtime or contract authority.
#[derive(Serialize)]
pub struct ActualGoNativeBodyObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    #[serde(flatten)]
    observation: GoNativeBodyObservation,
    value_domain_semantics: &'static str,
    value_domains: Vec<FunctionDomain>,
}

impl ActualGoNativeBodyObservation {
    pub(super) fn inspect_flow(&self, binding: &str) -> Option<NativeScalarFlowObservation> {
        let mut matches = self
            .observation
            .lowered_bodies()
            .flatten()
            .filter(|body| body.binding() == binding);
        let body = matches.next()?;
        matches
            .next()
            .is_none()
            .then(|| observe_lowered_native_scalar_flow(body))
    }

    pub(super) fn derive(observation: GoNativeBodyObservation) -> Self {
        let value_domains = observation
            .lowered_bodies()
            .enumerate()
            .map(|(function_index, body)| FunctionDomain::derive(function_index, body))
            .collect();
        Self {
            schema: "urn:fortress:derived:v1:go-native-body",
            schema_version: 1,
            observation,
            value_domain_semantics: "CONSERVATIVE_SCALAR_RETURN_UPPER_BOUND",
            value_domains,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum FunctionDomain {
    Inferred {
        function_index: usize,
        binding: String,
        domain: GoOutputDomain,
    },
    Unavailable {
        function_index: usize,
        binding: Option<String>,
        reason: DomainLimitation,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DomainLimitation {
    BodyUnavailable,
    InferenceUnavailable,
}

impl FunctionDomain {
    fn derive(function_index: usize, body: Option<&NativeScalarBody>) -> Self {
        let Some(body) = body else {
            return Self::Unavailable {
                function_index,
                binding: None,
                reason: DomainLimitation::BodyUnavailable,
            };
        };
        let binding = body.binding().to_owned();
        let Some(domain) = infer_native_scalar_output(body)
            .and_then(|domain| GoOutputDomain::from_inference(body.result(), domain))
        else {
            return Self::Unavailable {
                function_index,
                binding: Some(binding),
                reason: DomainLimitation::InferenceUnavailable,
            };
        };
        Self::Inferred {
            function_index,
            binding,
            domain,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum GoOutputDomain {
    Boolean {
        type_id: String,
        values: Vec<bool>,
    },
    Integer {
        type_id: String,
        intervals: Vec<DecimalInterval>,
        excluded: Vec<String>,
    },
}

#[derive(Serialize)]
struct DecimalInterval {
    min: String,
    max: String,
}

impl GoOutputDomain {
    fn from_inference(scalar: NativeScalar, domain: SemanticDomain) -> Option<Self> {
        match (scalar, domain) {
            (NativeScalar::Bool, SemanticDomain::Boolean { type_id, values }) => {
                Some(Self::Boolean { type_id, values })
            }
            (
                NativeScalar::SignedI64,
                SemanticDomain::Integer {
                    type_id,
                    intervals,
                    excluded,
                },
            ) => {
                let intervals = intervals
                    .into_iter()
                    .map(|interval| {
                        Some(DecimalInterval {
                            min: i64_decimal(interval.lower())?,
                            max: i64_decimal(interval.upper())?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                let excluded = excluded
                    .into_iter()
                    .map(i64_decimal)
                    .collect::<Option<Vec<_>>>()?;
                Some(Self::Integer {
                    type_id,
                    intervals,
                    excluded,
                })
            }
            _ => None,
        }
    }
}

fn i64_decimal(value: i128) -> Option<String> {
    // RFC 8785 number serialization cannot represent both signed 64-bit endpoints.
    i64::try_from(value).ok().map(|exact| exact.to_string())
}
