//! Exact supported-scope qualification metadata, separate from application proof.
//!
//! This reader never evaluates benchmark source or imports expected answers.
//! An admitted automated report covers only its exact frozen scope; it cannot
//! promote Standard defaults or supply application execution evidence.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;

/// Exact independently supplied identities required for report reuse.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationInputs {
    /// Named content identities, not machine paths, timestamps or producer names.
    pub identities: BTreeMap<String, String>,
}

const REQUIRED_IDENTITIES: &[&str] = &[
    "analyzer",
    "candidate_source",
    "catalog",
    "contexts",
    "corpus",
    "harness",
    "heldout_selection",
    "native_source",
    "oracle",
    "outcomes",
    "profiles",
    "protocol",
    "registry",
    "schemas",
    "staged_cli",
    "supported_scope",
    "toolchain",
];

/// Explicit deterministic denominators; none is a population accuracy estimate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCounts {
    /// All preregistered cases, including uncertainty and unsupported strata.
    pub declared_cases: u64,
    /// Cases with a completed retained observation.
    pub completed_cases: u64,
    /// Cases whose expected result is a mandatory supported control.
    pub required_cases: u64,
    /// Mandatory controls matching their independent expected outcome.
    pub required_passed: u64,
    /// All mismatches, including nonfavorable expected endpoints.
    pub mismatches: u64,
    /// Positive raw contradictions, not inferred process execution.
    pub positive: u64,
    /// Supported negative conclusions.
    pub negative: u64,
    /// Negative subset conditional on accepted research assumptions, not independent absence.
    pub conditional_negative: u64,
    /// Explicit uncertainty, including unsupported analysis.
    pub unknown: u64,
    /// Known absence of an applicable executable subject.
    pub not_applicable: u64,
    /// Explicit failed-input observations.
    pub invalid: u64,
    /// Driver failures, distinct from invalid source controls.
    pub execution_failures: u64,
    /// Authored ALLOW authority without absence claims.
    pub authorization: u64,
    /// Scopes with no authored evaluative policy.
    pub undeclared: u64,
    /// Original source-content/path/span/operation identities.
    pub distinct_source_sites: u64,
    /// Actual claim instances, reported separately from source sites.
    pub claims: u64,
    /// Actual causal paths, reported separately from independent sites.
    pub causal_paths: u64,
    /// Preregistered directed source-replacement relations.
    pub declared_mutations: u64,
    /// Relations whose independently scored endpoints were checked.
    pub exercised_mutations: u64,
    /// Cold/prepared/reused canonical comparisons completed successfully.
    pub equal_differentials: u64,
    /// Registered execution metadata alone never improves semantic outcomes.
    pub equal_metadata_controls: u64,
    /// Invalid inputs rejected equally by cold and uncached preparation ports.
    pub invalid_port_equivalences: u64,
    /// Pinned public scopes with a real expected positive original-source witness.
    pub external_positive_scopes: u64,
}

/// Honest assurance limits of a deterministic automated qualification envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationLimits {
    /// This protocol has no independent human adjudication.
    pub independent_human_adjudication: bool,
    /// Only null is representable: deterministic fixtures are not probability samples.
    #[serde(deserialize_with = "required_null")]
    pub population_precision: Option<()>,
    /// No real-world false-positive estimate is justified by this protocol.
    #[serde(deserialize_with = "required_null")]
    pub real_world_false_positive_rate: Option<()>,
    /// No sampling-based confidence claim is justified by this protocol.
    #[serde(deserialize_with = "required_null")]
    pub statistical_confidence: Option<()>,
    /// No independent external assurance follows from unsigned local evaluation.
    pub independent_external_assurance: bool,
    /// Nonempty explicit capability, historical-population and holdout limitations.
    pub reasons: Vec<String>,
}

/// Caller-provided report metadata; parsing alone does not establish admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// PASS, FAIL or INCOMPLETE; failed observations are retained, never selected as PASS.
    pub status: String,
    /// Exact declared scope identifier, not a whole-language claim.
    pub scope_id: String,
    /// Complete requalification inputs independently checked by the consumer.
    pub inputs: QualificationInputs,
    /// Reconstructable counts over all frozen strata.
    pub counts: QualificationCounts,
    /// Explicit limits; no human or statistical assurance inflation.
    pub limitations: QualificationLimits,
}

/// Predeclared capability envelope; expected case answers belong to Testing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedScope {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    /// Exact scope identity, never a whole-language accuracy claim.
    pub scope_id: String,
    /// Qualified operation families in canonical order.
    pub effects: Vec<String>,
    /// Frozen supported language/configuration strata.
    pub strata: Vec<String>,
    /// Mandatory limitations and unqualified capabilities.
    pub exclusions: Vec<String>,
    /// Qualified metadata alone never changes Standard default enforcement.
    pub promotes_default_blocking: bool,
    /// Independent human empirical validation remains future work.
    pub human_validation: String,
}

impl SupportedScope {
    /// Parses bounded, duplicate-free caller-supplied scope metadata.
    ///
    /// # Errors
    /// Rejects unknown fields, malformed ordering and exaggerated scope claims.
    pub fn from_json_str(source: &str) -> Result<Self, String> {
        bounded_json(source)?;
        let value: Self = serde_json::from_str(source).map_err(|e| e.to_string())?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != "urn:fortress:schema:v1:supported-qualification-scope"
            || self.schema_version != 1
            || self.scope_id.trim().is_empty()
            || self.promotes_default_blocking
            || self.human_validation != "RECOMMENDED_FUTURE_RESEARCH_NOT_PERFORMED"
            || [&self.effects, &self.strata, &self.exclusions]
                .into_iter()
                .any(|v| {
                    v.is_empty()
                        || v.len() > 256
                        || v.iter().any(|s| s.trim().is_empty() || s.len() > 4096)
                        || v.windows(2).any(|p| p[0] >= p[1])
                })
        {
            return Err("unsupported, vacuous or inflated qualification scope".into());
        }
        Ok(())
    }

    /// Exact canonical metadata identity; does not authenticate its origin.
    ///
    /// # Errors
    /// Reports serialization failure without substituting an identity.
    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
    }
}

fn bounded_json(source: &str) -> Result<(), String> {
    if source.len() > 1024 * 1024 {
        return Err("qualification metadata exceeds 1 MiB".into());
    }
    crate::wire::reject_duplicate_json_keys(source).map_err(|e| e.to_string())
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn required_null<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<()>, D::Error> {
    <()>::deserialize(deserializer).map(|()| None)
}

impl QualificationManifest {
    /// Canonical content identity, without authenticating the report producer.
    ///
    /// # Errors
    /// Reports serialization failure without substituting an identity.
    pub fn digest(&self) -> Result<String, String> {
        let bytes = serde_json_canonicalizer::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
    }
    /// Parses metadata without claiming that the report has been admitted.
    ///
    /// # Errors
    /// Rejects oversized or malformed records, duplicate keys and unknown fields.
    pub fn from_json_str(source: &str) -> Result<Self, String> {
        bounded_json(source)?;
        serde_json::from_str(source).map_err(|e| e.to_string())
    }

    /// Admits exact externally supplied current premises for one frozen scope.
    ///
    /// The caller owns the trust decision about current identities and report
    /// bytes. Parsing, a matching hash and local PASS do not authenticate anyone.
    ///
    /// # Errors
    /// Rejects stale or mismatched scope metadata and all invalid PASS claims.
    pub fn admit_for(
        &self,
        expected: &QualificationInputs,
        scope: &SupportedScope,
    ) -> Result<(), String> {
        scope.validate()?;
        self.validate_for(expected, &scope.scope_id)?;
        if expected.identities.get("supported_scope") != Some(&scope.digest()?) {
            return Err("qualification supported-scope binding differs".into());
        }
        Ok(())
    }
    /// Checks exact scope/input reuse without inspecting expected benchmark answers.
    ///
    /// # Errors
    /// Rejects stale, incomplete, failed, vacuous or exaggerated qualification claims.
    pub fn validate_for(
        &self,
        expected: &QualificationInputs,
        scope_id: &str,
    ) -> Result<(), String> {
        if self.schema != "urn:fortress:derived:v1:semantic-qualification"
            || self.schema_version != 1
            || self.status != "PASS"
            || self.scope_id != scope_id
            || self.inputs != *expected
            || self.inputs.identities.len() != REQUIRED_IDENTITIES.len()
            || REQUIRED_IDENTITIES
                .iter()
                .any(|name| !self.inputs.identities.get(*name).is_some_and(|v| digest(v)))
        {
            return Err("qualification identity is stale, incomplete or unqualified".into());
        }
        let c = &self.counts;
        if [
            c.declared_cases,
            c.completed_cases,
            c.required_cases,
            c.required_passed,
            c.mismatches,
            c.positive,
            c.negative,
            c.conditional_negative,
            c.unknown,
            c.not_applicable,
            c.invalid,
            c.execution_failures,
            c.authorization,
            c.undeclared,
            c.distinct_source_sites,
            c.claims,
            c.causal_paths,
            c.declared_mutations,
            c.exercised_mutations,
            c.equal_differentials,
            c.equal_metadata_controls,
            c.invalid_port_equivalences,
            c.external_positive_scopes,
        ]
        .into_iter()
        .any(|value| value > 9_007_199_254_740_991)
        {
            return Err("qualification count exceeds exact machine-number range".into());
        }
        let endpoints = [
            c.positive,
            c.negative,
            c.unknown,
            c.not_applicable,
            c.invalid,
            c.execution_failures,
            c.authorization,
            c.undeclared,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add);
        if c.declared_cases == 0
            || c.completed_cases != c.declared_cases
            || endpoints != Some(c.completed_cases)
            || c.required_cases == 0
            || c.required_cases > c.declared_cases
            || c.required_passed != c.required_cases
            || c.mismatches != 0
            || c.execution_failures != 0
            || c.positive == 0
            || c.negative == 0
            || c.conditional_negative >= c.negative
            || c.distinct_source_sites == 0
            || c.claims == 0
            || c.causal_paths == 0
            || c.declared_mutations == 0
            || c.exercised_mutations != c.declared_mutations
            || c.equal_differentials
                .checked_add(c.invalid_port_equivalences)
                != Some(c.declared_cases)
            || c.equal_metadata_controls != c.equal_differentials
            || c.invalid_port_equivalences > c.invalid
            || c.external_positive_scopes == 0
        {
            return Err(
                "qualification omitted cases, mutations, contrasts or real witnesses".into(),
            );
        }
        let l = &self.limitations;
        if l.independent_human_adjudication
            || l.independent_external_assurance
            || l.population_precision.is_some()
            || l.real_world_false_positive_rate.is_some()
            || l.statistical_confidence.is_some()
            || l.reasons.is_empty()
            || l.reasons.iter().any(|r| r.trim().is_empty())
            || l.reasons.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("qualification claims unsupported assurance or omits limitations".into());
        }
        Ok(())
    }
}
