//! Read-only explicit source transfers from one admitted native scalar body.

use serde::Serialize;

use crate::program_semantics::native_body::{NativeBodyOutcome, NativeScalarBody};
use crate::program_semantics::{
    ProgramBody, ProgramProvenance, ProgramSourceLocation, ProgramStatement, canonical_fact_id,
};

use super::{
    FlowAuthority, FlowEdge, FlowNode, InformationFlowCoverage, body_edges, expression_sources,
};

const MAX_EDGES: usize = 4096;
const MAX_CONDITIONS: usize = 1024;
const MAX_REPORT_BYTES: usize = 128 * 1024;

/// Scoped source-site observations for one exact native scalar occurrence.
///
/// These facts are outside the canonical flow and operation lanes. They never
/// carry production witnesses, resolve a policy sink, or establish absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeScalarFlowObservation {
    schema: &'static str,
    occurrence_ref: Option<String>,
    projection_ref: Option<String>,
    explicit_data_coverage: InformationFlowCoverage,
    control_influence_coverage: InformationFlowCoverage,
    classification_authority: FlowAuthority,
    facts: Facts,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum Facts {
    Observed {
        explicit_data_edges: Vec<FlowEdge>,
        condition_inputs: Vec<ConditionInputs>,
    },
    Unavailable {
        code: String,
        location: Option<ProgramSourceLocation>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConditionInputs {
    sources: Vec<FlowNode>,
    provenance: ProgramProvenance,
}

impl NativeScalarFlowObservation {
    /// Returns an exact occurrence-bound projection identity when facts were observed.
    #[must_use]
    pub fn projection_ref(&self) -> Option<&str> {
        self.projection_ref.as_deref()
    }

    /// Returns the recorded source-site data-edge count when available.
    ///
    /// A zero count establishes no absence property.
    #[must_use]
    pub fn explicit_edge_count(&self) -> Option<usize> {
        match &self.facts {
            Facts::Observed {
                explicit_data_edges,
                ..
            } => Some(explicit_data_edges.len()),
            Facts::Unavailable { .. } => None,
        }
    }

    /// Returns the coverage of control influence rather than condition syntax.
    #[must_use]
    pub const fn control_influence_coverage(&self) -> InformationFlowCoverage {
        self.control_influence_coverage
    }

    /// Returns deterministic bounded bytes for the observational projection.
    ///
    /// # Errors
    /// Returns an error if JSON encoding or its resource bound fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        let bytes = serde_json_canonicalizer::to_vec(self)?;
        if bytes.len() > MAX_REPORT_BYTES {
            return Err(serde_json::Error::io(std::io::Error::other(
                "native scalar transfer report exceeds its byte bound",
            )));
        }
        Ok(bytes)
    }

    fn unavailable(
        occurrence_ref: Option<String>,
        code: String,
        location: Option<ProgramSourceLocation>,
    ) -> Self {
        Self {
            schema: "fortress:native-scalar-flow-observation:1",
            occurrence_ref,
            projection_ref: None,
            explicit_data_coverage: InformationFlowCoverage::Unknown,
            control_influence_coverage: InformationFlowCoverage::Unsupported,
            classification_authority: FlowAuthority::Unknown,
            facts: Facts::Unavailable { code, location },
        }
    }
}

/// Projects the existing explicit-data derivation for a bounded native body.
///
/// Statement sites retain their exact provenance. Reassignments remain separate
/// sites. Condition inputs are observable, while control influence stays
/// unsupported. No transitive flow, reachability, or proof is calculated.
#[must_use]
pub fn observe_native_scalar_flow(outcome: &NativeBodyOutcome) -> NativeScalarFlowObservation {
    let body = match outcome {
        NativeBodyOutcome::Lowered(body) => body,
        NativeBodyOutcome::Unavailable(reason) => {
            return NativeScalarFlowObservation::unavailable(
                None,
                reason.code().into(),
                reason.location().cloned(),
            );
        }
    };
    observe_lowered_native_scalar_flow(body)
}

pub(crate) fn observe_lowered_native_scalar_flow(
    body: &NativeScalarBody,
) -> NativeScalarFlowObservation {
    let occurrence = body.binding();
    let unavailable = || {
        NativeScalarFlowObservation::unavailable(
            Some(occurrence.into()),
            "RESOURCE_LIMIT".into(),
            None,
        )
    };
    let program = body.body();
    // The admitted body already bounds raw source, shape depth, and tokens.
    let mut explicit_data_edges = Vec::new();
    body_edges(program, program.statements(), &mut explicit_data_edges);
    let mut condition_inputs = Vec::new();
    collect_conditions(program, program.statements(), &mut condition_inputs);
    if explicit_data_edges.len() > MAX_EDGES || condition_inputs.len() > MAX_CONDITIONS {
        return unavailable();
    }
    explicit_data_edges.sort();
    explicit_data_edges.dedup();
    let mut report = NativeScalarFlowObservation {
        schema: "fortress:native-scalar-flow-observation:1",
        occurrence_ref: Some(occurrence.into()),
        projection_ref: None,
        explicit_data_coverage: InformationFlowCoverage::Partial,
        control_influence_coverage: InformationFlowCoverage::Unsupported,
        classification_authority: FlowAuthority::Unknown,
        facts: Facts::Observed {
            explicit_data_edges,
            condition_inputs,
        },
    };
    let Ok(encoded) = report.to_canonical_json() else {
        return unavailable();
    };
    let identity = canonical_fact_id("native_scalar_flow_observation:v1", &report);
    // The ASCII identity replaces the existing JSON null value.
    if encoded.len().saturating_add(identity.len()) > MAX_REPORT_BYTES {
        return unavailable();
    }
    report.projection_ref = Some(identity);
    report
}

fn collect_conditions(
    body: &ProgramBody,
    statements: &[ProgramStatement],
    conditions: &mut Vec<ConditionInputs>,
) {
    for statement in statements {
        if let ProgramStatement::If {
            condition,
            then_branch,
            else_branch,
            provenance,
        } = statement
        {
            conditions.push(ConditionInputs {
                sources: expression_sources(body.symbol(), condition),
                provenance: provenance.clone(),
            });
            collect_conditions(body, then_branch, conditions);
            collect_conditions(body, else_branch, conditions);
        }
    }
}
