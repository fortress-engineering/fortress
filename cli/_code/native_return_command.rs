//! Canonical CLI view of an exact, original authored native return observation.

use fortress_core::native_return_observation::{
    AuthoredNativeReturnComparison, AuthoredNativeReturnObservation,
    NativeReturnComparisonLimitation,
};
use fortress_core::portable::canonical;
use fortress_core::program_semantics::native_callable::NativeCallableOutcome;
use fortress_core::semantic_analysis::NativeBooleanReturn;
use serde_json::{Value, json};

const SCHEMA: &str = "urn:fortress:derived:v1:native-return-inspection";

pub(super) fn serialize(report: &AuthoredNativeReturnObservation) -> Result<Vec<u8>, String> {
    let subject = match &report.subject {
        NativeCallableOutcome::Linked(link) => json!({
            "status": "LINKED",
            "language": link.language(),
            "namespace": link.namespace(),
            "function": link.function(),
            "source_path": link.source_path(),
            "source_ref": link.source_ref(),
            "slot_ref": link.slot_ref(),
            "link_ref": link.link_ref(),
            "origin_ref": link.origin_ref(),
            "exchange_ref": link.exchange_ref(),
            "body_occurrence": link.body().binding(),
            "original_declared_owner": link.declared_source_owner().map(|owner| owner.owner()),
            "evaluation_key": link.evaluation(),
        }),
        NativeCallableOutcome::Unavailable(reason) => json!({
            "status": "UNAVAILABLE",
            "reason": reason,
        }),
    };
    canonical(&json!({
        "$schema": SCHEMA,
        "schema_version": 1,
        "scope": "ACTUAL_ORIGINAL_SOURCE_SCOPED_NATIVE_BOOLEAN_RETURN",
        "runtime_execution": "NOT_RUN",
        "authority_scope": "ORIGINAL_DECLARED_LOGICAL_MODULE",
        "canonical_finding_or_certificate": "NOT_ISSUED",
        "source_binding": {
            "source_view_ref": report.source_view_ref,
            "source_manifest_digest": report.source_manifest_digest,
            "authority_binding_digest": report.authority_binding_digest,
        },
        "subject": subject,
        "comparison": comparison(&report.comparison),
    }))
    .map_err(|failure| failure.to_string())
}

fn comparison(result: &AuthoredNativeReturnComparison) -> Value {
    match result {
        AuthoredNativeReturnComparison::Observed(observed) => json!({
            "status": "OBSERVED",
            "author": observed.author,
            "contract_path": observed.contract_path,
            "contract_ref": observed.contract_ref,
            "required_return": observed.required_return,
            "observed_return": match observed.observed_return {
                NativeBooleanReturn::MatchesRequiredValue => "MATCHES_REQUIRED_VALUE",
                NativeBooleanReturn::ExcludesRequiredValue => "EXCLUDES_REQUIRED_VALUE",
                NativeBooleanReturn::Unresolved => "UNRESOLVED",
            },
        }),
        AuthoredNativeReturnComparison::Unavailable(reason) => json!({
            "status": "UNAVAILABLE",
            "reason": limitation(*reason),
        }),
    }
}

const fn limitation(reason: NativeReturnComparisonLimitation) -> &'static str {
    use NativeReturnComparisonLimitation as Limit;
    match reason {
        Limit::SubjectUnavailable => "SUBJECT_UNAVAILABLE",
        Limit::OwnerUnavailable => "OWNER_UNAVAILABLE",
        Limit::UnsupportedContractScope => "UNSUPPORTED_CONTRACT_SCOPE",
        Limit::InvalidContractDocument => "INVALID_CONTRACT_DOCUMENT",
        Limit::RequirementUnavailable => "REQUIREMENT_UNAVAILABLE",
        Limit::ForeignContractOwner => "FOREIGN_CONTRACT_OWNER",
        Limit::AmbiguousRequirement => "AMBIGUOUS_REQUIREMENT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fortress_core::program_semantics::native_callable::NativeCallableLimitation;

    #[test]
    fn unavailable_subject_keeps_original_source_binding_and_no_favorable_result() {
        let source_view_ref = format!("sha256:{}", "a".repeat(64));
        let source_manifest_digest = format!("sha256:{}", "b".repeat(64));
        let authority_binding_digest = format!("sha256:{}", "c".repeat(64));
        let report = AuthoredNativeReturnObservation {
            source_view_ref: source_view_ref.clone(),
            source_manifest_digest: source_manifest_digest.clone(),
            authority_binding_digest: authority_binding_digest.clone(),
            subject: NativeCallableOutcome::Unavailable(NativeCallableLimitation::AmbiguousSubject),
            comparison: AuthoredNativeReturnComparison::Unavailable(
                NativeReturnComparisonLimitation::SubjectUnavailable,
            ),
        };
        let bytes = serialize(&report).unwrap();
        assert_eq!(bytes, serialize(&report).unwrap());
        let actual: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            actual,
            json!({
                "$schema": "urn:fortress:derived:v1:native-return-inspection",
                "schema_version": 1,
                "scope": "ACTUAL_ORIGINAL_SOURCE_SCOPED_NATIVE_BOOLEAN_RETURN",
                "runtime_execution": "NOT_RUN",
                "authority_scope": "ORIGINAL_DECLARED_LOGICAL_MODULE",
                "canonical_finding_or_certificate": "NOT_ISSUED",
                "source_binding": {
                    "source_view_ref": source_view_ref,
                    "source_manifest_digest": source_manifest_digest,
                    "authority_binding_digest": authority_binding_digest,
                },
                "subject": {"status":"UNAVAILABLE","reason":"AMBIGUOUS_SUBJECT"},
                "comparison": {"status":"UNAVAILABLE","reason":"SUBJECT_UNAVAILABLE"},
            })
        );
    }
}
