//! Native Boolean body inspection of a retained, unapplied candidate.

use serde::Serialize;

use super::{CandidateWorkspace, HypotheticalEvaluation, NativeCandidateSelection, error};
use crate::audit::{
    NativeAuthorityScope, NativeObservationBinding, bind_native_observation_source,
};
use crate::migration_governance::MigrationError;
use crate::observation::SourceView;
use crate::portable::digest;
use crate::project::EvaluationKey;
use crate::semantic_analysis::NativeBooleanSensitivity;

/// Exact postimage and declaration selected by the local native inspection host.
#[derive(Clone, Copy)]
pub struct NativeCandidateSubject<'a> {
    /// Canonical candidate-relative path of an ordinary source file.
    pub source_path: &'a str,
    /// Independently selected SHA-256 of the exact proposed source bytes.
    pub source_ref: &'a str,
    /// The native frontend's exact case-sensitive function name.
    pub function: &'a str,
}

/// A compile-only observation attached to one exact retained proposal.
#[derive(Serialize)]
pub struct HypotheticalNativeBodyInspection {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    status: &'static str,
    actual_state: bool,
    language: &'static str,
    proposal_ref: String,
    proposal_digest: String,
    overlay_context_ref: String,
    original_source_view_ref: String,
    candidate_source_view_ref: String,
    original_authority_ref: String,
    candidate_authority_ref: String,
    source_path: String,
    source_ref: String,
    function: String,
    comparison: &'static str,
    runtime_execution: &'static str,
    actual_certificate: &'static str,
    native: NativeCandidateBody,
}

impl NativeCandidateBody {
    pub(crate) fn analyzed(
        evaluation_key: EvaluationKey,
        response_ref: String,
        body: Option<&crate::program_semantics::native_body::NativeScalarBody>,
    ) -> Self {
        let sensitivity = body.map(crate::semantic_analysis::inspect_native_boolean_sensitivity);
        Self {
            evaluation_key,
            response_ref,
            status: if body.is_some() {
                "ADMITTED"
            } else {
                "BODY_UNAVAILABLE"
            },
            sensitivity,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct NativeCandidateBody {
    evaluation_key: EvaluationKey,
    response_ref: String,
    status: &'static str,
    sensitivity: Option<NativeBooleanSensitivity>,
}

pub(crate) fn inspect_hypothetical_native_body(
    workspace: &CandidateWorkspace,
    selected: NativeCandidateSelection<'_>,
    subject: NativeCandidateSubject<'_>,
    language: &'static str,
    inspect: impl FnOnce(
        &SourceView,
        &NativeObservationBinding,
        &HypotheticalEvaluation,
    ) -> Result<NativeCandidateBody, MigrationError>,
) -> Result<HypotheticalNativeBodyInspection, MigrationError> {
    workspace.inspect_retained_native(
        selected.client,
        selected.candidate,
        selected.cancelled,
        |base, target, proposal| {
            if subject.function.is_empty()
                || subject.function.len() > 240
                || !subject
                    .function
                    .bytes()
                    .enumerate()
                    .all(|(position, byte)| {
                        byte == b'_'
                            || byte.is_ascii_alphabetic()
                            || (position != 0 && byte.is_ascii_digit())
                    })
            {
                return Err(error(
                    "NATIVE_SUBJECT_MISMATCH",
                    "candidate function selector is invalid",
                ));
            }
            if subject.source_path.len() > 4096 {
                return Err(error(
                    "NATIVE_SUBJECT_MISMATCH",
                    "candidate source selector exceeds its path bound",
                ));
            }
            let present = target.bytes(subject.source_path);
            if present.is_none_or(|bytes| digest(bytes) != subject.source_ref) {
                return Err(error(
                    "NATIVE_SUBJECT_MISMATCH",
                    "candidate source does not match the exact selected postimage",
                ));
            }
            let original =
                bind_native_observation_source(base, language, NativeAuthorityScope::Observation)
                    .map_err(native_error)?;
            let candidate =
                bind_native_observation_source(target, language, NativeAuthorityScope::Observation)
                    .map_err(native_error)?;
            let native = inspect(target, &candidate, proposal)?;
            Ok(HypotheticalNativeBodyInspection {
                schema: "urn:fortress:derived:v1:hypothetical-native-body-inspection",
                schema_version: 1,
                status: "PROPOSED",
                actual_state: false,
                language,
                proposal_ref: proposal.evaluation_ref().into(),
                proposal_digest: proposal.candidate_digest().into(),
                overlay_context_ref: proposal.context_ref().into(),
                original_source_view_ref: base.digest().into(),
                candidate_source_view_ref: target.digest().into(),
                original_authority_ref: original.authority_digest,
                candidate_authority_ref: candidate.authority_digest,
                source_path: subject.source_path.into(),
                source_ref: subject.source_ref.into(),
                function: subject.function.into(),
                comparison: "NOT_COMPARED",
                runtime_execution: "NOT_RUN",
                actual_certificate: "NOT_ISSUED",
                native,
            })
        },
    )
}

pub(crate) fn native_error(failure: impl std::fmt::Display) -> MigrationError {
    error("NATIVE_OBSERVATION_UNAVAILABLE", failure.to_string())
}
