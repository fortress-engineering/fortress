//! One bounded immutable comparison projection and paging cache; no endpoint analysis.
use super::{
    MAX_PAGE_SIZE, PageParameters, QueryError, QueryPage, QueryRecord, QueryService,
    TransitionPage, TransitionParameters, check_cancelled, digest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
pub(super) type ComparisonCache = Mutex<BTreeMap<String, Arc<PreparedComparison>>>;
pub(super) struct PreparedComparison {
    analysis_ref: String,
    description: Value,
    records: Vec<QueryRecord>,
    bytes: usize,
}
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
impl QueryService {
    /// Adds explicitly prepared immutable comparison inputs before serving requests.
    /// # Errors
    /// Refuses malformed inputs, resource limits and multiple builder attachments.
    pub fn with_comparison_states(
        mut self,
        states: Vec<crate::state_governance::ComparisonState>,
    ) -> Result<Self, QueryError> {
        if !self.comparison_states.is_empty() || states.len() > 16 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "at most sixteen comparison inputs may be attached once",
            ));
        }
        let mut bytes = 0usize;
        for state in states {
            bytes = bytes
                .checked_add(state.to_canonical_bytes().map_err(convert)?.len())
                .filter(|n| *n <= 128 * 1024 * 1024)
                .ok_or_else(|| {
                    QueryError::new("RESOURCE_LIMIT", "comparison input bytes exceed admission")
                })?;
            let id = state.digest().map_err(convert)?;
            self.comparison_identities.insert(
                id.clone(),
                (
                    state.subject_identity().map_err(convert)?,
                    state.governing_identity().map_err(convert)?,
                ),
            );
            self.comparison_states.insert(id, state);
        }
        self.state_ref = digest(
            &json!({"query_input":self.state_ref,"comparison_inputs":self.comparison_states.keys().collect::<Vec<_>>()}),
        )?;
        Ok(self)
    }
    /// Lists exact loaded identities, software/governing projections and original refs.
    #[must_use]
    pub fn comparison_state_inventory(&self) -> Vec<Value> {
        self.comparison_states.iter().map(|(id,s)|json!({"state_ref":id,"software_subject_ref":self.comparison_identities[id].0,"governing_ref":self.comparison_identities[id].1,"source_ref":s.source_ref,"origin_ref":s.origin_ref,"status":s.view.as_ref().map(|v|v.status),"retained_pair":s.retained_application.is_some(),"assets_available":s.assets.is_some()})).collect()
    }
    pub(super) fn compare_transition(
        &self,
        p: &TransitionParameters,
        cancelled: &AtomicBool,
    ) -> Result<TransitionPage, QueryError> {
        check_cancelled(cancelled)?;
        let key = digest(&json!([
            p.from_state_ref,
            p.to_state_ref,
            p.comparison_context,
            p.counterfactual_state_refs
        ]))?;
        let cached = self
            .comparison_cache
            .lock()
            .map_err(|_| QueryError::new("UNAVAILABLE", "comparison cache poisoned"))?
            .get(&key)
            .cloned();
        let prepared = if let Some(result) = cached {
            result
        } else {
            let result = Arc::new(self.prepare_transition(p, cancelled)?);
            let mut cache = self
                .comparison_cache
                .lock()
                .map_err(|_| QueryError::new("UNAVAILABLE", "comparison cache poisoned"))?;
            while !cache.is_empty()
                && (cache.len() >= 4
                    || cache
                        .values()
                        .map(|v| v.bytes)
                        .sum::<usize>()
                        .saturating_add(result.bytes)
                        > MAX_CACHE_BYTES)
            {
                cache.pop_first();
            }
            cache.insert(key, Arc::clone(&result));
            result
        };
        check_cancelled(cancelled)?;
        let signature = digest(&json!([self.state_ref, prepared.analysis_ref]))?;
        let deltas = page_transition(&prepared.records, &p.page, &signature, cancelled)?;
        Ok(TransitionPage {
            analysis_ref: prepared.analysis_ref.clone(),
            description: prepared.description.clone(),
            deltas,
        })
    }
    fn prepare_transition(
        &self,
        p: &TransitionParameters,
        cancelled: &AtomicBool,
    ) -> Result<PreparedComparison, QueryError> {
        let from = self
            .comparison_states
            .get(&p.from_state_ref)
            .ok_or_else(|| QueryError::new("NOT_FOUND", "before state is not explicitly loaded"))?;
        let to = self
            .comparison_states
            .get(&p.to_state_ref)
            .ok_or_else(|| QueryError::new("NOT_FOUND", "after state is not explicitly loaded"))?;
        let context = self.comparison_context(p)?;
        let result =
            crate::state_governance::compare_states_cancellable(from, to, &context, cancelled)
                .map_err(convert)?;
        let analysis_ref = result.digest().map_err(convert)?;
        let mut records = Vec::new();
        for (category, deltas) in [
            ("semantic", &result.semantic_deltas),
            ("coverage", &result.coverage_deltas),
            ("evidence", &result.evidence_deltas),
            ("finding", &result.finding_deltas),
        ] {
            for d in deltas {
                check_cancelled(cancelled)?;
                records.push(QueryRecord {
                    id: format!("{category}:{}:{}", d.category, d.id),
                    kind: category.into(),
                    scope_ref: analysis_ref.clone(),
                    value: json!(d),
                });
            }
        }
        for record in &result.retirement_evidence {
            records.push(QueryRecord {
                id: format!("retirement:{}", record.finding_id),
                kind: "retirement".into(),
                scope_ref: analysis_ref.clone(),
                value: json!(record),
            });
        }
        for (i, reason) in result.incomparabilities.iter().enumerate() {
            records.push(QueryRecord {
                id: format!("incomparability:{i}"),
                kind: "incomparability".into(),
                scope_ref: analysis_ref.clone(),
                value: json!({"reason":reason}),
            });
        }
        let counts = [
            ("semantic", result.semantic_deltas.len()),
            ("coverage", result.coverage_deltas.len()),
            ("evidence", result.evidence_deltas.len()),
            ("finding", result.finding_deltas.len()),
            ("retirement", result.retirement_evidence.len()),
            ("incomparabilities", result.incomparabilities.len()),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        let description = json!({"from_state":result.from_state,"to_state":result.to_state,"comparison_context":result.comparison_context,"input_deltas":result.input_deltas,"counts":counts,"strengthenings":result.strengthenings.len(),"weakenings":result.weakenings.len(),"required_authorizations":result.required_authorizations,"limitations":result.limitations,"semantic_version":result.semantic_version,"derived_non_authoritative":true});
        let bytes = serde_json::to_vec(&records)
            .map_err(|e| QueryError::new("INVALID_RESULT", e.to_string()))?
            .len()
            .saturating_add(
                serde_json::to_vec(&description)
                    .map_err(|e| QueryError::new("INVALID_RESULT", e.to_string()))?
                    .len(),
            );
        if bytes > MAX_CACHE_BYTES {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "prepared comparison exceeds bounded retention",
            ));
        }
        check_cancelled(cancelled)?;
        Ok(PreparedComparison {
            analysis_ref,
            description,
            records,
            bytes,
        })
    }
    fn comparison_context(
        &self,
        p: &TransitionParameters,
    ) -> Result<crate::state_governance::ComparisonContext, QueryError> {
        let mut context = p.comparison_context.clone();
        if p.counterfactual_state_refs.len() > 4 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "too many counterfactual references",
            ));
        }
        for reference in &p.counterfactual_state_refs {
            let state = self.comparison_states.get(reference).ok_or_else(|| {
                QueryError::new(
                    "NOT_FOUND",
                    "counterfactual state was not explicitly loaded",
                )
            })?;
            let view = state.view.as_ref().ok_or_else(|| {
                QueryError::new(
                    "UNAVAILABLE",
                    "counterfactual requires a complete retained StateView",
                )
            })?;
            if view.application.is_none() {
                return Err(QueryError::new(
                    "UNAVAILABLE",
                    "counterfactual has no evaluated authority",
                ));
            }
            let identities = &self.comparison_identities[reference];
            context
                .counterfactuals
                .push(crate::state_governance::Counterfactual {
                    subject_ref: identities.0.clone().ok_or_else(|| {
                        QueryError::new(
                            "UNAVAILABLE",
                            "counterfactual software inputs are incomplete",
                        )
                    })?,
                    authority_ref: identities.1.clone().ok_or_else(|| {
                        QueryError::new(
                            "UNAVAILABLE",
                            "counterfactual governing inputs are incomplete",
                        )
                    })?,
                    view: view.clone(),
                    assets: state.assets.clone(),
                });
        }
        Ok(context)
    }
}
fn convert(error: crate::state_governance::TransitionError) -> QueryError {
    QueryError::new(error.code, error.message)
}
pub(super) fn page_transition(
    records: &[QueryRecord],
    p: &PageParameters,
    signature: &str,
    cancelled: &AtomicBool,
) -> Result<QueryPage, QueryError> {
    if !(1..=MAX_PAGE_SIZE).contains(&p.limit) {
        return Err(QueryError::new(
            "RESOURCE_LIMIT",
            "page size exceeds admission",
        ));
    }
    let offset = if let Some(cursor) = &p.cursor {
        let (prefix, position) = cursor
            .rsplit_once(':')
            .ok_or_else(|| QueryError::new("INVALID_CURSOR", "invalid transition continuation"))?;
        if prefix != signature {
            return Err(QueryError::new(
                "INVALID_CURSOR",
                "continuation belongs to another comparison",
            ));
        }
        position
            .parse::<usize>()
            .map_err(|_| QueryError::new("INVALID_CURSOR", "invalid transition offset"))?
    } else {
        0
    };
    if offset > records.len() {
        return Err(QueryError::new(
            "INVALID_CURSOR",
            "continuation exceeds complete result",
        ));
    }
    let total = records.len();
    let end = offset.saturating_add(p.limit).min(total);
    let mut page = Vec::new();
    for record in &records[offset..end] {
        check_cancelled(cancelled)?;
        page.push(record.clone());
    }
    Ok(QueryPage {
        total,
        offset,
        records: page,
        next_cursor: if end < total {
            Some(format!("{signature}:{end}"))
        } else {
            None
        },
    })
}
