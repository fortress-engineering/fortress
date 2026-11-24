//! Finite return comparison under the admitted exact Boolean input model.

use serde::Serialize;

use super::{NATIVE_BOOL, SemanticDomain, interpret_native_body, native_analysis_context};
use crate::program_semantics::native_body::{NativeScalar, NativeScalarBody};

const MAX_PARAMETERS: usize = 4;

/// Finite returned-value sensitivity for one admitted native body occurrence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeBooleanSensitivity {
    /// Every valuation under the selected input model has a singleton return bound.
    Complete {
        /// Exact admitted body occurrence and frontend premises.
        occurrence_ref: String,
        /// Number of concretely selected Boolean input valuations considered.
        valuation_count: usize,
        /// Parameter outcomes in the original declaration order.
        parameters: Vec<NativeBooleanParameterSensitivity>,
    },
    /// No complete finite return comparison was established.
    Unavailable {
        /// Exact admitted body occurrence and frontend premises.
        occurrence_ref: String,
        /// Why a complete table could not be established.
        reason: NativeBooleanSensitivityReason,
    },
}

/// Limitation at the finite Boolean return comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeBooleanSensitivityReason {
    /// The model requires between one and four declared parameters.
    ParameterCount,
    /// All parameters, locals, and the return must have exact Boolean scope.
    UnsupportedScalarScope,
    /// A valuation may fall through, incur an opaque result, or yield a nonsingleton bound.
    IncompleteValuation,
}

/// Result for one parameter, using pairs that hold the other parameters fixed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeBooleanParameterSensitivity {
    /// Admitted parameter name in the original declaration order.
    pub parameter: String,
    /// Conditional return comparison for this parameter.
    pub disposition: NativeBooleanParameterDisposition,
}

/// Returned-value comparison under the selected finite model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeBooleanParameterDisposition {
    /// The established return bounds differ for the first matching pair of valuations.
    ReturnChanges {
        /// Input tuple for the false member of this pair, in declaration order.
        inputs_with_parameter_false: Vec<bool>,
        /// Input tuple for the true member of this pair, in declaration order.
        inputs_with_parameter_true: Vec<bool>,
        /// Exact modeled return when this parameter is false.
        return_with_parameter_false: bool,
        /// Exact modeled return when this parameter is true.
        return_with_parameter_true: bool,
    },
    /// Each pair returns the same Boolean within the admitted finite model.
    SameReturnAcrossPairedInputs,
}

/// Compares the possible returned value under every admitted exact Boolean valuation.
///
/// The existing domain interpreter receives singleton inputs. A single incomplete
/// or ambiguous result prevents all comparisons. Pairs vary only one parameter.
/// The witness order uses declaration order, with the first parameter the low bit.
/// The result describes a closed returned-value model, without runtime execution,
/// general control-flow, effects, or information-flow noninterference claims.
#[must_use]
pub fn inspect_native_boolean_sensitivity(body: &NativeScalarBody) -> NativeBooleanSensitivity {
    let unavailable = |reason| NativeBooleanSensitivity::Unavailable {
        occurrence_ref: body.binding().into(),
        reason,
    };
    let count = body.parameters().len();
    if !(1..=MAX_PARAMETERS).contains(&count) {
        return unavailable(NativeBooleanSensitivityReason::ParameterCount);
    }
    if body.result() != NativeScalar::Bool
        || body
            .parameters()
            .iter()
            .chain(body.locals())
            .any(|(_, scalar)| *scalar != NativeScalar::Bool)
    {
        return unavailable(NativeBooleanSensitivityReason::UnsupportedScalarScope);
    }

    let context = native_analysis_context(body);
    let valuation_count = 1 << count;
    let mut returns = Vec::with_capacity(valuation_count);
    for mask in 0..valuation_count {
        let inputs = body
            .parameters()
            .iter()
            .zip(valuation(mask, count))
            .map(|((name, _), value)| (name.clone(), SemanticDomain::boolean(NATIVE_BOOL, [value])))
            .collect();
        let Some(SemanticDomain::Boolean { type_id, values }) =
            interpret_native_body(body, &context, inputs)
        else {
            return unavailable(NativeBooleanSensitivityReason::IncompleteValuation);
        };
        let [result] = values.as_slice() else {
            return unavailable(NativeBooleanSensitivityReason::IncompleteValuation);
        };
        if type_id != NATIVE_BOOL {
            return unavailable(NativeBooleanSensitivityReason::IncompleteValuation);
        }
        returns.push(*result);
    }

    NativeBooleanSensitivity::Complete {
        occurrence_ref: body.binding().into(),
        valuation_count,
        parameters: body
            .parameters()
            .iter()
            .enumerate()
            .map(|(index, (name, _))| NativeBooleanParameterSensitivity {
                parameter: name.clone(),
                disposition: compare_pairs(&returns, index, count),
            })
            .collect(),
    }
}

fn valuation(mask: usize, count: usize) -> impl Iterator<Item = bool> {
    (0..count).map(move |index| mask & (1 << index) != 0)
}

fn compare_pairs(
    returns: &[bool],
    parameter_index: usize,
    count: usize,
) -> NativeBooleanParameterDisposition {
    let bit = 1 << parameter_index;
    for (without, &return_with_false) in returns.iter().enumerate() {
        if without & bit == 0 {
            let with = without | bit;
            let return_with_true = returns[with];
            if return_with_false != return_with_true {
                return NativeBooleanParameterDisposition::ReturnChanges {
                    inputs_with_parameter_false: valuation(without, count).collect(),
                    inputs_with_parameter_true: valuation(with, count).collect(),
                    return_with_parameter_false: return_with_false,
                    return_with_parameter_true: return_with_true,
                };
            }
        }
    }
    NativeBooleanParameterDisposition::SameReturnAcrossPairedInputs
}
