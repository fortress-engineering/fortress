//! Exact-profile sufficiency over complete manifests and externally admitted evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::certification::EvidenceClass;
use crate::declaration::{
    ConformanceDeclaration, DeclarationBinding, DeclarationError, DeclarationTruth,
    DimensionManifest, canonical, canonical_strings, is_digest, strictly_increasing,
};
use crate::proof::ProofGraph;

/// Current exact-profile assessment with explicit selected evidence inputs.
pub const ASSESSMENT_SCHEMA: &str = "urn:fortress:derived:v2:profile-assessment";
/// Retained initial assessment meaning and byte representation.
pub const ASSESSMENT_SCHEMA_V1: &str = "urn:fortress:derived:v1:profile-assessment";

/// Closed assessment algebra; valid reporting does not imply satisfaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentDecision {
    /// All required obligations have complete accepted support.
    Satisfied,
    /// A supported current contradiction defeats a required proposition.
    NotSatisfied,
    /// Required current support cannot be established.
    NotEvaluable,
    /// Structural or trusted-authority validation failed.
    Invalid,
}

/// Semantic proposition evidenced by a leaf, separate from evidence class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceProposition {
    /// A truthful observation that asserts no evaluative or execution proposition.
    ObservationOnly,
    /// A known required premise whose support is unavailable.
    Unavailable,
    /// An exact scoped absence proposition.
    NoSupportedViolation,
    /// A complete supported positive contradiction.
    SupportedViolation,
    /// A required verification execution completed successfully.
    ExecutionSucceeded,
    /// Accepted required verification execution actually failed.
    ExecutionFailed,
}

/// Immutable evidence metadata; none of its strings authenticate its producer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentEvidence {
    /// Exact evidence identity supplied by its owning producer.
    pub id: String,
    /// Exact upstream premise identity; admission identities also bind its scope.
    pub source_ref: String,
    /// Exact evaluated source/context/authority.
    pub binding: DeclarationBinding,
    /// Exact claim/rule/requirement scope.
    pub scope_ref: String,
    /// Evidence authority, never inferred from a name.
    pub evidence_class: EvidenceClass,
    /// Proposition actually supported by this leaf.
    pub proposition: EvidenceProposition,
    /// Exact retained payload identity verified outside this untrusted record.
    pub payload_digest: String,
    /// Explicit conditional premises.
    pub assumptions: Vec<String>,
    /// Explicit expiry; the assessor never reads a hidden wall clock.
    pub valid_until: Option<u64>,
}

impl AssessmentEvidence {
    /// Identifies all scoped metadata, separately from its raw payload digest.
    ///
    /// # Errors
    /// Rejects public canonical serialization failures.
    pub fn metadata_digest(&self) -> Result<String, DeclarationError> {
        Ok(format!("sha256:{:x}", Sha256::digest(canonical(self)?)))
    }
}

/// Trust and payload acceptance supplied by the host, outside candidate authority.
#[derive(Clone, Debug, Default, Serialize)]
pub struct EvidenceAcceptancePolicy {
    /// Exact leaf-to-payload bindings independently verified by the caller.
    pub verified_payloads: BTreeMap<String, String>,
    /// Exact metadata digests independently checked against each admitted payload.
    pub verified_metadata: BTreeMap<String, String>,
    /// Evidence whose producer authenticity the caller actually authenticated.
    pub authenticated_evidence: BTreeSet<String>,
    /// Explicitly admitted conditional premises.
    pub accepted_assumptions: BTreeSet<String>,
    /// Explicit assessment-time input required for time-limited evidence.
    pub assessment_time: Option<u64>,
}

/// A profile predicate; authorization and nonapplicability cannot satisfy it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObligationPredicate {
    /// The exact registered rule check succeeded; not a Module absence proof.
    RuleCheck,
    /// Complete scoped support for no supported violation.
    Conformance,
    /// Complete scoped support for a positive or negative conclusion.
    Evaluability,
    /// Actual successful verification in the selected evidence class.
    SuccessfulExecution,
}

/// One required obligation compiled from trusted selected profile authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileObligation {
    /// Complete manifest identity, present regardless of the outcome.
    pub id: String,
    /// Exact semantic/evidence scope.
    pub scope_ref: String,
    /// Required semantic proposition.
    pub predicate: ObligationPredicate,
    /// Required authority class.
    pub evidence_class: EvidenceClass,
    /// Whether the selected profile requires authenticated provenance.
    pub authenticated_producer_required: bool,
    /// Current upstream proof alternatives; absence means missing support.
    pub proof: Option<ProofGraph>,
}

/// Caller-provided exact authority; never reconstructed from the declaration itself.
#[derive(Clone, Debug)]
pub struct ExpectedProfileAssessment {
    /// Complete immutable artifact requirements compiled by trusted producers.
    pub artifacts: Vec<crate::declaration::DeclarationArtifact>,
    /// Exact source/context/authority expected by the caller.
    pub binding: DeclarationBinding,
    /// Independently compiled reporting manifest.
    pub dimensions: DimensionManifest,
    /// Digest of the complete selected scoped profile composition.
    pub profile_digest: String,
    /// Complete required obligations, including unsatisfied and unavailable ones.
    pub obligations: Vec<ProfileObligation>,
}

/// Exact typed cause that withholds profile satisfaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentBlockerCode {
    /// The upstream raw truth has a supported contradiction.
    SupportedViolation,
    /// Complete relevant support is absent.
    RequiredEvidenceMissing,
    /// Evidence belongs to another source or authority binding.
    StaleEvidence,
    /// Evidence belongs to another `ProgramContext`.
    IncompatibleContext,
    /// The caller did not admit this exact leaf/payload.
    UntrustedEvidence,
    /// A required authentication premise is absent.
    ProducerNotAuthenticated,
    /// A conditional premise was not admitted by the caller.
    AssumptionNotAccepted,
    /// Explicit time-bound evidence cannot be admitted at the supplied time.
    EvidenceExpiredOrTimeMissing,
    /// Self-declared reporting differs from the caller's trusted manifest.
    TrustedManifestMismatch,
    /// Evidence class or semantic predicate is unrelated.
    IncompatibleEvidence,
    /// The proof graph is structurally invalid.
    InvalidProof,
    /// Admitted current verification failed, separate from a Module policy violation.
    ExecutionFailed,
}

/// Complete outcome of one required obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObligationAssessment {
    /// Required obligation identity.
    pub id: String,
    /// Independent sufficiency/conformance conclusion.
    pub decision: AssessmentDecision,
    /// Exact blockers; no fabricated violation for uncertainty.
    pub blockers: Vec<AssessmentBlockerCode>,
}

/// Exact-profile conclusion about a particular immutable declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAssessment {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Digest of exact emitted declaration bytes.
    pub declaration_digest: String,
    /// Complete selected profile composition.
    pub profile_digest: String,
    /// Exact source/context/authority.
    pub binding: DeclarationBinding,
    /// Digest of every required obligation, including proof alternatives.
    pub obligation_manifest_digest: String,
    /// Every required obligation has an explicit outcome.
    pub obligations: Vec<ObligationAssessment>,
    /// Strict deterministic aggregation of all required obligations.
    pub decision: AssessmentDecision,
    /// Digest of explicit time, admitted payloads, authentication and assumptions.
    pub acceptance_policy_digest: String,
    /// Exact selected provider input set; absent only in historical v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_input_digest: Option<String>,
    /// Structural authority blockers also apply to an empty obligation set.
    pub blockers: Vec<AssessmentBlockerCode>,
}

impl ProfileAssessment {
    /// Exact wire edition; historical readers never infer adjacent meanings.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Assesses raw reporting against external authority and admitted proof leaves.
    ///
    /// # Errors
    /// Rejects structurally invalid declarations, duplicate inputs or serialization.
    pub fn evaluate(
        declaration: &ConformanceDeclaration,
        expected: &ExpectedProfileAssessment,
        evidence: &[AssessmentEvidence],
        acceptance: &EvidenceAcceptancePolicy,
    ) -> Result<Self, DeclarationError> {
        Self::evaluate_with_inputs(
            declaration,
            expected,
            evidence,
            acceptance,
            &empty_evidence_input_digest(&expected.binding)?,
        )
    }

    /// Evaluates the complete trusted obligations against an explicit exact
    /// provider input identity. This argument is supplied by the host, not
    /// reconstructed from a candidate's favorable subset.
    ///
    /// # Errors
    /// Rejects malformed declarations, proof identities and input-set digests.
    pub fn evaluate_with_inputs(
        declaration: &ConformanceDeclaration,
        expected: &ExpectedProfileAssessment,
        evidence: &[AssessmentEvidence],
        acceptance: &EvidenceAcceptancePolicy,
        evidence_input_digest: &str,
    ) -> Result<Self, DeclarationError> {
        declaration.validate()?;
        if !is_digest(evidence_input_digest) {
            return crate::declaration::invalid("invalid provider input identity");
        }
        strictly_increasing(expected.obligations.iter().map(|o| &o.id))?;
        strictly_increasing(evidence.iter().map(|e| &e.id))?;
        if !is_digest(&expected.profile_digest) {
            return Err(DeclarationError::Invalid(
                "invalid expected profile identity".into(),
            ));
        }
        for leaf in evidence {
            if leaf.id.is_empty()
                || leaf.source_ref.is_empty()
                || leaf.scope_ref.is_empty()
                || !is_digest(&leaf.payload_digest)
            {
                return Err(DeclarationError::Invalid(
                    "invalid evidence identity".into(),
                ));
            }
            canonical_strings(&leaf.assumptions)?;
        }
        let mismatch = declaration.binding != expected.binding
            || declaration.required_dimension_manifest != expected.dimensions
            || declaration.proof_manifest != expected.artifacts;
        let known = evidence
            .iter()
            .map(|e| e.id.clone())
            .collect::<BTreeSet<_>>();
        let mut outcomes = Vec::new();
        for obligation in &expected.obligations {
            let outcome = if mismatch {
                ObligationAssessment {
                    id: obligation.id.clone(),
                    decision: AssessmentDecision::Invalid,
                    blockers: vec![AssessmentBlockerCode::TrustedManifestMismatch],
                }
            } else {
                assess_obligation(
                    obligation,
                    declaration,
                    expected,
                    evidence,
                    acceptance,
                    &known,
                )
            };
            outcomes.push(outcome);
        }
        let decision = [
            AssessmentDecision::Invalid,
            AssessmentDecision::NotSatisfied,
            AssessmentDecision::NotEvaluable,
        ]
        .into_iter()
        .find(|state| outcomes.iter().any(|o| o.decision == *state))
        .unwrap_or(if mismatch {
            AssessmentDecision::Invalid
        } else {
            AssessmentDecision::Satisfied
        });
        Ok(Self {
            schema: ASSESSMENT_SCHEMA.into(),
            schema_version: 2,
            declaration_digest: declaration.digest()?,
            profile_digest: expected.profile_digest.clone(),
            binding: expected.binding.clone(),
            obligation_manifest_digest: format!(
                "sha256:{:x}",
                Sha256::digest(canonical(&expected.obligations)?)
            ),
            obligations: outcomes,
            decision,
            acceptance_policy_digest: format!(
                "sha256:{:x}",
                Sha256::digest(canonical(acceptance)?)
            ),
            evidence_input_digest: Some(evidence_input_digest.to_owned()),
            blockers: if mismatch {
                vec![AssessmentBlockerCode::TrustedManifestMismatch]
            } else {
                vec![]
            },
        })
    }

    /// Returns canonical public bytes after checking all aggregate invariants.
    ///
    /// # Errors
    /// Rejects invalid headers, bindings, ordering or decision aggregation.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DeclarationError> {
        self.validate()?;
        canonical(self)
    }

    /// Reads strict historical v1/current v2; integrity is not authority or replay.
    ///
    /// # Errors
    /// Rejects malformed public JSON and inconsistent aggregate decisions.
    pub fn from_json_str(source: &str) -> Result<Self, DeclarationError> {
        let value: Self = crate::wire::parse_public_json(source)
            .map_err(|e| DeclarationError::Invalid(e.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Checks internal shape; independently replay evaluation to establish sufficiency.
    ///
    /// # Errors
    /// Rejects malformed or inconsistent records.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        let header_valid = match self.schema_version {
            1 => {
                self.schema == ASSESSMENT_SCHEMA_V1
                    && self.evidence_input_digest.is_none()
                    && !self
                        .blockers
                        .contains(&AssessmentBlockerCode::ExecutionFailed)
                    && self
                        .obligations
                        .iter()
                        .all(|o| !o.blockers.contains(&AssessmentBlockerCode::ExecutionFailed))
            }
            2 => {
                self.schema == ASSESSMENT_SCHEMA
                    && self.evidence_input_digest.as_deref().is_some_and(is_digest)
            }
            _ => false,
        };
        if !header_valid {
            return crate::declaration::invalid("unsupported assessment");
        }
        for id in [
            &self.declaration_digest,
            &self.profile_digest,
            &self.obligation_manifest_digest,
            &self.acceptance_policy_digest,
            &self.binding.subject_ref,
            &self.binding.context_ref,
            &self.binding.authority_ref,
        ] {
            if !is_digest(id) {
                return crate::declaration::invalid("invalid assessment identity");
            }
        }
        strictly_increasing(self.obligations.iter().map(|o| &o.id))?;
        strictly_increasing(self.blockers.iter())?;
        for o in &self.obligations {
            strictly_increasing(o.blockers.iter())?;
            if o.id.is_empty()
                || (o.decision == AssessmentDecision::Satisfied) != o.blockers.is_empty()
            {
                return crate::declaration::invalid("invalid obligation outcome");
            }
        }
        let expected = if self.blockers.is_empty() {
            [
                AssessmentDecision::Invalid,
                AssessmentDecision::NotSatisfied,
                AssessmentDecision::NotEvaluable,
            ]
            .into_iter()
            .find(|s| self.obligations.iter().any(|o| o.decision == *s))
            .unwrap_or(AssessmentDecision::Satisfied)
        } else {
            AssessmentDecision::Invalid
        };
        if expected != self.decision {
            return crate::declaration::invalid("inconsistent assessment decision");
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn assess_obligation(
    obligation: &ProfileObligation,
    declaration: &ConformanceDeclaration,
    expected: &ExpectedProfileAssessment,
    evidence: &[AssessmentEvidence],
    policy: &EvidenceAcceptancePolicy,
    known: &BTreeSet<String>,
) -> ObligationAssessment {
    let result = |decision, code: Option<AssessmentBlockerCode>| ObligationAssessment {
        id: obligation.id.clone(),
        decision,
        blockers: code.into_iter().collect(),
    };
    let Some(proof) = &obligation.proof else {
        return result(
            AssessmentDecision::NotEvaluable,
            Some(AssessmentBlockerCode::RequiredEvidenceMissing),
        );
    };
    if proof.validate(known).is_err() {
        return result(
            AssessmentDecision::Invalid,
            Some(AssessmentBlockerCode::InvalidProof),
        );
    }
    let claims = declaration
        .claims
        .iter()
        .filter(|c| c.scope_ref == obligation.scope_ref)
        .collect::<Vec<_>>();
    let contradiction = claims
        .iter()
        .any(|c| c.truth == DeclarationTruth::SupportedViolation);
    let kind = match obligation.predicate {
        ObligationPredicate::RuleCheck => Some(crate::declaration::DeclarationClaimKind::RuleCheck),
        ObligationPredicate::Conformance | ObligationPredicate::Evaluability => {
            Some(crate::declaration::DeclarationClaimKind::SemanticPolicy)
        }
        ObligationPredicate::SuccessfulExecution => None,
    };
    if kind.is_some_and(|required| claims.is_empty() || claims.iter().any(|c| c.kind != required)) {
        return result(
            AssessmentDecision::NotEvaluable,
            Some(AssessmentBlockerCode::IncompatibleEvidence),
        );
    }
    let raw_predicate = match obligation.predicate {
        ObligationPredicate::RuleCheck => {
            !claims.is_empty()
                && claims.iter().all(|c| {
                    c.semantic_claim.is_none() && c.truth == DeclarationTruth::NoSupportedViolation
                })
                && !contradiction
        }
        ObligationPredicate::Conformance => {
            !claims.is_empty()
                && claims
                    .iter()
                    .all(|c| c.truth == DeclarationTruth::NoSupportedViolation)
                && !contradiction
        }
        ObligationPredicate::Evaluability => {
            !claims.is_empty()
                && claims.iter().all(|c| {
                    matches!(
                        c.truth,
                        DeclarationTruth::NoSupportedViolation
                            | DeclarationTruth::SupportedViolation
                    )
                })
        }
        ObligationPredicate::SuccessfulExecution => true,
    };
    if !raw_predicate && !contradiction {
        return result(
            AssessmentDecision::NotEvaluable,
            Some(AssessmentBlockerCode::RequiredEvidenceMissing),
        );
    }
    let required_refs = proof
        .nodes
        .iter()
        .flat_map(|node| {
            node.required_refs
                .iter()
                .map(crate::proof::EvidenceReference::id)
        })
        .collect::<BTreeSet<_>>();
    let mut accepted = BTreeMap::new();
    let mut rejection = AssessmentBlockerCode::RequiredEvidenceMissing;
    for leaf in evidence {
        if !required_refs.contains(leaf.id.as_str()) {
            continue;
        }
        let proposition = match obligation.predicate {
            ObligationPredicate::RuleCheck | ObligationPredicate::Conformance if contradiction => {
                leaf.proposition == EvidenceProposition::SupportedViolation
            }
            ObligationPredicate::RuleCheck | ObligationPredicate::Conformance => {
                leaf.proposition == EvidenceProposition::NoSupportedViolation
            }
            ObligationPredicate::Evaluability => matches!(
                leaf.proposition,
                EvidenceProposition::NoSupportedViolation | EvidenceProposition::SupportedViolation
            ),
            ObligationPredicate::SuccessfulExecution => {
                matches!(
                    leaf.proposition,
                    EvidenceProposition::ExecutionSucceeded | EvidenceProposition::ExecutionFailed
                )
            }
        };
        let reason = if leaf.binding.context_ref != expected.binding.context_ref {
            Some(AssessmentBlockerCode::IncompatibleContext)
        } else if leaf.binding != expected.binding {
            Some(AssessmentBlockerCode::StaleEvidence)
        } else if leaf.scope_ref != obligation.scope_ref {
            Some(AssessmentBlockerCode::IncompatibleEvidence)
        } else if leaf.proposition == EvidenceProposition::Unavailable {
            Some(AssessmentBlockerCode::RequiredEvidenceMissing)
        } else if leaf.evidence_class != obligation.evidence_class
            || !proposition
            || (obligation.predicate != ObligationPredicate::SuccessfulExecution
                && !claims
                    .iter()
                    .any(|c| c.proof_refs.contains(&leaf.source_ref)))
        {
            Some(AssessmentBlockerCode::IncompatibleEvidence)
        } else if policy.verified_payloads.get(&leaf.id) != Some(&leaf.payload_digest) {
            Some(AssessmentBlockerCode::UntrustedEvidence)
        } else if obligation.authenticated_producer_required
            && !policy.authenticated_evidence.contains(&leaf.id)
        {
            Some(AssessmentBlockerCode::ProducerNotAuthenticated)
        } else if leaf
            .assumptions
            .iter()
            .any(|a| !policy.accepted_assumptions.contains(a))
        {
            Some(AssessmentBlockerCode::AssumptionNotAccepted)
        } else if leaf
            .valid_until
            .is_some_and(|until| policy.assessment_time.is_none_or(|now| now > until))
        {
            Some(AssessmentBlockerCode::EvidenceExpiredOrTimeMissing)
        } else if policy.verified_metadata.get(&leaf.id) != leaf.metadata_digest().ok().as_ref() {
            Some(AssessmentBlockerCode::UntrustedEvidence)
        } else {
            None
        };
        if let Some(code) = reason {
            rejection = code;
        } else {
            accepted.insert(
                leaf.id.clone(),
                if obligation.predicate == ObligationPredicate::SuccessfulExecution
                    && leaf.proposition == EvidenceProposition::ExecutionFailed
                {
                    crate::proof::ProofState::Refuted
                } else {
                    crate::proof::ProofState::Satisfied
                },
            );
        }
    }
    match proof.evaluate(known, &accepted) {
        Ok(crate::proof::ProofState::Satisfied) => {}
        Ok(crate::proof::ProofState::Refuted) => {
            return result(
                AssessmentDecision::NotSatisfied,
                Some(AssessmentBlockerCode::ExecutionFailed),
            );
        }
        Ok(crate::proof::ProofState::Unknown) => {
            return result(AssessmentDecision::NotEvaluable, Some(rejection));
        }
        Err(_) => {
            return result(
                AssessmentDecision::Invalid,
                Some(AssessmentBlockerCode::InvalidProof),
            );
        }
    }
    if matches!(
        obligation.predicate,
        ObligationPredicate::Conformance | ObligationPredicate::RuleCheck
    ) && contradiction
    {
        result(
            AssessmentDecision::NotSatisfied,
            Some(AssessmentBlockerCode::SupportedViolation),
        )
    } else if raw_predicate {
        result(AssessmentDecision::Satisfied, None)
    } else {
        result(
            AssessmentDecision::NotEvaluable,
            Some(AssessmentBlockerCode::RequiredEvidenceMissing),
        )
    }
}

/// Exact empty provider input identity, preserving source/context/authority binding.
///
/// # Errors
/// Propagates a public canonical serialization failure.
pub fn empty_evidence_input_digest(
    binding: &DeclarationBinding,
) -> Result<String, DeclarationError> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical(&(
            "provider-evidence-input-set-v1",
            binding,
            Vec::<serde_json::Value>::new()
        ))?)
    ))
}
