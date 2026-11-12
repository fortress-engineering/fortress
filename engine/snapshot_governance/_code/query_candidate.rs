//! Explicitly preloaded immutable proposals. Querying never starts candidate analysis.
use super::{
    CandidateParameters, ExplanationPage, QueryError, QueryRecord, QueryService, check_cancelled,
    digest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

pub(super) struct LoadedCandidate {
    record_ref: String,
    description: Value,
    records: Vec<QueryRecord>,
}
pub(super) type LoadedCandidates = BTreeMap<String, LoadedCandidate>;

impl QueryService {
    /// Attaches exact proposals once, explicitly, before serving. They never replace actual input.
    /// # Errors
    /// Refuses malformed, duplicate or excessive proposal records.
    pub fn with_candidates(
        mut self,
        candidates: Vec<crate::candidate::HypotheticalEvaluation>,
    ) -> Result<Self, QueryError> {
        if !self.candidates.is_empty() || candidates.len() > 16 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "attach at most sixteen immutable proposals once",
            ));
        }
        let mut bytes = 0usize;
        let mut record_count = self.records.len();
        let mut index_bytes = self.index_bytes;
        for candidate in candidates {
            let canonical = candidate
                .to_canonical_bytes()
                .map_err(|e| QueryError::new(e.code, e.message))?;
            bytes = bytes
                .checked_add(canonical.len())
                .filter(|n| *n <= 128 * 1024 * 1024)
                .ok_or_else(|| {
                    QueryError::new("RESOURCE_LIMIT", "loaded proposal bytes exceed admission")
                })?;
            let value: Value = serde_json::from_slice(&canonical)
                .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?;
            let id = candidate.evaluation_ref().to_owned();
            let record_ref = digest(&value)?;
            let axes = candidate.transition().input_deltas.iter().map(|a| json!({"axis":a.axis,"change":a.change,"complete":a.complete,"input_count":a.input_ids.len()})).collect::<Vec<_>>();
            let description = json!({"evaluation_ref":id,"record_ref":record_ref,"candidate_digest":candidate.candidate_digest(),"status":"PROPOSED","actual_state":false,"base_generation":value["base_generation"],"base_subject":value["base_subject"],"context_ref":value["context_ref"],"trusted_base_authority":value["trusted_base_authority"],"predicted_state_ref":value["predicted_state_ref"],"axes":axes,"authenticity":"UNVERIFIED","evidence":"Complete original proposal fields, authorization errors and limitations are paged as exact JSON pointers; no proof, runtime execution, authorization or actual certification is inferred."});
            let mut records = Vec::new();
            flatten(
                &id,
                "",
                &value,
                &mut records,
                &mut record_count,
                &mut index_bytes,
            )?;
            if self
                .candidates
                .insert(
                    id,
                    LoadedCandidate {
                        record_ref,
                        description,
                        records,
                    },
                )
                .is_some()
            {
                return Err(QueryError::new(
                    "AMBIGUOUS_IDENTITY",
                    "duplicate candidate identity",
                ));
            }
        }
        self.index_bytes = index_bytes;
        self.state_ref = digest(
            &json!({"query_input":self.state_ref,"proposed_candidates":self.candidates.iter().map(|(id,c)| (id,&c.record_ref)).collect::<Vec<_>>()}),
        )?;
        Ok(self)
    }
    pub(super) fn inspect_candidate(
        &self,
        parameters: &CandidateParameters,
        cancelled: &AtomicBool,
    ) -> Result<ExplanationPage, QueryError> {
        check_cancelled(cancelled)?;
        if let Some(id) = &parameters.candidate_ref {
            let loaded = self.candidates.get(id).ok_or_else(|| {
                QueryError::new(
                    "NOT_FOUND",
                    "candidate is not explicitly loaded; inspection never initiates analysis",
                )
            })?;
            let signature = digest(&json!([self.state_ref, id, "candidate"]))?;
            Ok(ExplanationPage {
                selector: id.clone(),
                description: loaded.description.clone(),
                evidence: super::transition::page_transition(
                    &loaded.records,
                    &parameters.page,
                    &signature,
                    cancelled,
                )?,
            })
        } else {
            let records = self
                .candidates
                .iter()
                .map(|(id, c)| QueryRecord {
                    id: id.clone(),
                    kind: "PROPOSED_CANDIDATE".into(),
                    scope_ref: self.state_ref.clone(),
                    value: c.description.clone(),
                })
                .collect::<Vec<_>>();
            let signature = digest(&json!([self.state_ref, "candidate-inventory"]))?;
            Ok(ExplanationPage {
                selector: "candidate-inventory".into(),
                description: json!({"actual_state":false,"status":"PROPOSED","analysis_initiated":false}),
                evidence: super::transition::page_transition(
                    &records,
                    &parameters.page,
                    &signature,
                    cancelled,
                )?,
            })
        }
    }
}
fn flatten(
    id: &str,
    pointer: &str,
    value: &Value,
    output: &mut Vec<QueryRecord>,
    count: &mut usize,
    bytes: &mut usize,
) -> Result<(), QueryError> {
    match value {
        Value::Object(fields) if !fields.is_empty() => {
            for (key, value) in fields {
                flatten(
                    id,
                    &format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1")),
                    value,
                    output,
                    count,
                    bytes,
                )?;
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (offset, value) in items.iter().enumerate() {
                flatten(
                    id,
                    &format!("{pointer}/{offset}"),
                    value,
                    output,
                    count,
                    bytes,
                )?;
            }
        }
        _ => {
            let charge = value
                .as_str()
                .map_or(16, str::len)
                .saturating_mul(6)
                .saturating_add(pointer.len().saturating_mul(2))
                .saturating_add(id.len().saturating_mul(2))
                .saturating_add(256);
            *count = count.saturating_add(1);
            *bytes = bytes.saturating_add(charge);
            if *count > 100_000 || *bytes > 64 * 1024 * 1024 {
                return Err(QueryError::new(
                    "RESOURCE_LIMIT",
                    "complete candidate field index exceeds query admission",
                ));
            }
            output.push(QueryRecord {
                id: format!("{id}#{pointer}"),
                kind: "PROPOSED_FIELD".into(),
                scope_ref: id.into(),
                value: json!({"pointer":pointer,"value":value}),
            });
        }
    }
    Ok(())
}
