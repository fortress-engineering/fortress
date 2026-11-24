//! Finite native-call composition using the existing domain interpreter.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::native_analysis_context;
use super::native_sensitivity::{
    MAX_PARAMETERS, NativeBooleanParameterSensitivity, boolean_return_table, boolean_scope,
    compare_boolean_parameters,
};
use crate::program_semantics::native_body::{NativeCallBindings, NativeScalarBody};

const MAX_BODIES: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_CALL_SITES: usize = 256;

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum NativeBooleanCallEvaluation {
    Complete {
        occurrence: String,
        parameters: Vec<String>,
        returns: Vec<bool>,
        dependency_occurrences: Vec<String>,
    },
    Unavailable {
        occurrence: String,
        reason: Unavailable,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Unavailable {
    MissingTargetBody,
    RecursiveDependency,
    AnalysisLimit,
    UnsupportedScalarScope,
    IncompleteValuation,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum NativeBooleanCallSensitivity {
    Complete {
        occurrence: String,
        valuation_count: usize,
        dependency_occurrences: Vec<String>,
        parameters: Vec<NativeBooleanParameterSensitivity>,
    },
    Unavailable {
        occurrence: String,
        reason: Unavailable,
    },
}

impl NativeBooleanCallEvaluation {
    pub(crate) fn into_sensitivity(self) -> NativeBooleanCallSensitivity {
        match self {
            Self::Complete {
                occurrence,
                parameters,
                returns,
                dependency_occurrences,
            } => NativeBooleanCallSensitivity::Complete {
                occurrence,
                valuation_count: returns.len(),
                dependency_occurrences,
                parameters: compare_boolean_parameters(
                    &returns,
                    parameters.iter().map(String::as_str),
                ),
            },
            Self::Unavailable { occurrence, reason } => {
                NativeBooleanCallSensitivity::Unavailable { occurrence, reason }
            }
        }
    }
}

/// Consume only exact call edges already admitted by the producer boundary.
/// Every syntactically admitted call in the selected transitive closure must
/// have a complete finite model, including calls in infeasible branches.
pub(crate) fn analyze_native_boolean_calls<'a>(
    body: &'a NativeScalarBody,
    targets: &NativeCallBindings<'a>,
) -> NativeBooleanCallEvaluation {
    let mut analysis = Composition {
        targets,
        returns: BTreeMap::new(),
        active: BTreeSet::new(),
        visited_sites: 0,
    };
    if let Err(reason) = analysis.visit(body) {
        return NativeBooleanCallEvaluation::Unavailable {
            occurrence: body.binding().into(),
            reason,
        };
    }
    let returns = analysis
        .returns
        .remove(body.binding())
        .expect("successful visit stores a result");
    NativeBooleanCallEvaluation::Complete {
        occurrence: body.binding().into(),
        parameters: body
            .parameters()
            .iter()
            .map(|(name, _)| name.clone())
            .collect(),
        returns,
        dependency_occurrences: analysis
            .returns
            .keys()
            .map(|key| (*key).to_owned())
            .collect(),
    }
}

struct Composition<'a, 't> {
    targets: &'t NativeCallBindings<'a>,
    returns: BTreeMap<&'a str, Vec<bool>>,
    active: BTreeSet<&'a str>,
    visited_sites: usize,
}

impl<'a> Composition<'a, '_> {
    fn visit(&mut self, body: &'a NativeScalarBody) -> Result<(), Unavailable> {
        if self.active.contains(body.binding()) {
            return Err(Unavailable::RecursiveDependency);
        }
        if self.returns.contains_key(body.binding()) {
            return Ok(());
        }
        self.visited_sites += body.bound_calls().len();
        if self.active.len() >= MAX_DEPTH
            || self.active.len() + self.returns.len() >= MAX_BODIES
            || self.visited_sites > MAX_CALL_SITES
        {
            return Err(Unavailable::AnalysisLimit);
        }
        if body.parameters().len() > MAX_PARAMETERS || !boolean_scope(body) {
            return Err(Unavailable::UnsupportedScalarScope);
        }
        self.active.insert(body.binding());
        for call in body.bound_calls() {
            let target = self
                .targets
                .target(body, call)
                .ok_or(Unavailable::MissingTargetBody)?;
            self.visit(target)?;
        }
        let mut tables = BTreeMap::new();
        for call in body.bound_calls() {
            let target = self
                .targets
                .target(body, call)
                .ok_or(Unavailable::MissingTargetBody)?;
            let values = self
                .returns
                .get(target.binding())
                .ok_or(Unavailable::MissingTargetBody)?;
            tables.insert(call.reference.as_str(), values.as_slice());
        }
        let mut context = native_analysis_context(body);
        context.native_call_tables = Some(&tables);
        let output =
            boolean_return_table(body, &context).ok_or(Unavailable::IncompleteValuation)?;
        self.active.remove(body.binding());
        self.returns.insert(body.binding(), output);
        Ok(())
    }
}
