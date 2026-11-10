//! Bounded inspection of existing lifecycle evidence and authored history; no analyzer or grants.
use super::{
    ExplainParameters, ExplanationPage, QueryError, QueryService, check_cancelled, digest,
};
use crate::finding_governance::{FindingGovernanceDocument, RetirementEvidenceV2};
use serde_json::json;
use std::sync::atomic::AtomicBool;
fn convert(e: impl std::fmt::Display) -> QueryError {
    QueryError::new("INVALID_INPUT", e.to_string())
}
fn lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        "retirement_evidence"
            | "baseline_admission"
            | "retired_finding"
            | "exception_review_authority"
    )
}
impl QueryService {
    /// Adds previously produced retirement results. Favorable records remain unauthenticated.
    /// # Errors
    /// Refuses malformed records, duplicate identities and existing shared resource limits.
    pub fn with_retirement_evidence(
        mut self,
        mut records: Vec<RetirementEvidenceV2>,
    ) -> Result<Self, QueryError> {
        if records.is_empty() {
            return Ok(self);
        }
        if records.len() > crate::finding_governance::MAX_GOVERNANCE_RECORDS {
            return Err(QueryError::new("RESOURCE_LIMIT", "retirement record limit"));
        }
        crate::finding_governance::lifecycle_bytes(&records).map_err(convert)?;
        records.sort_by(|a, b| {
            (
                &a.finding_id,
                &a.comparison_basis.from_state,
                &a.comparison_basis.to_state,
            )
                .cmp(&(
                    &b.finding_id,
                    &b.comparison_basis.from_state,
                    &b.comparison_basis.to_state,
                ))
        });
        let mut known = self
            .records
            .iter()
            .map(|r| r.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for record in records {
            let id = record.digest().map_err(convert)?;
            if !known.insert(id.clone()) {
                return Err(QueryError::new(
                    "IDENTITY_AMBIGUOUS",
                    "retirement evidence already attached",
                ));
            }
            self.add_record("retirement_evidence",&id,&record.finding_id,json!({"record":record,"inspection_authenticity":"NOT_REVERIFIED_PROVENANCE","proof_materialization":"REFERENCED_NOT_REVERIFIED","mutates_authority":false}))?;
        }
        self.finish_lifecycle_index()?;
        Ok(self)
    }
    /// Indexes the registered current authored authority, separately from selected historical results.
    /// No missing semantic anchors, authorization decisions or current conformance are invented.
    /// # Errors
    /// Refuses malformed authority and existing record/byte bounds.
    pub fn with_finding_authority(
        mut self,
        authority: &FindingGovernanceDocument,
    ) -> Result<Self, QueryError> {
        let reference = authority.authority_digest().map_err(convert)?;
        let start = self.records.len();
        if let Some(b) = authority.baseline() {
            for entry in b.active_entries() {
                let id = format!("baseline:{}", entry.finding_id());
                self.add_record("baseline_admission",id,entry.finding_id(),json!({"original_entry":entry,"anchor":authority.lifecycle().and_then(|r|r.anchors.get(entry.finding_id())),"current_authored_governance_ref":reference,"semantic_resolution":"NOT_INFERRED","authorization":"NOT_REVERIFIED"}))?;
            }
            for entry in b.retired_entries() {
                let value = serde_json::to_value(entry).map_err(convert)?;
                let finding = value["finding_id"]
                    .as_str()
                    .ok_or_else(|| QueryError::new("INVALID_INPUT", "retired identity missing"))?;
                self.add_record("retired_finding",format!("retired:{finding}"),finding,json!({"original_identity":entry,"retirement_history":authority.lifecycle().and_then(|r|r.retirements.get(finding)),"current_authored_governance_ref":reference,"reintroduction":"BLOCKS_WITHOUT_A_NEW_APPLICABLE_EXCEPTION","authorization":"NOT_REVERIFIED"}))?;
            }
        }
        for e in authority.exceptions() {
            self.add_record("exception_review_authority",format!("exception:{}",e.id()),e.finding_id(),json!({"authored_exception":e,"original_review":authority.lifecycle().and_then(|r|r.exception_reviews.get(e.id())),"current_authored_governance_ref":reference,"authorization":"UNVERIFIED_REFERENCE","current_applicability":"REQUIRES_COMPARABLE_SCOPE_AND_EXPLICIT_REVIEW_TIME","raw_conformance":"UNCHANGED"}))?;
        }
        if self.records.len() != start {
            self.finish_lifecycle_index()?;
        }
        Ok(self)
    }
    fn finish_lifecycle_index(&mut self) -> Result<(), QueryError> {
        self.records
            .sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        if self
            .records
            .windows(2)
            .any(|w| w[0].kind == w[1].kind && w[0].id == w[1].id)
        {
            return Err(QueryError::new(
                "IDENTITY_AMBIGUOUS",
                "lifecycle authority already attached",
            ));
        }
        self.state_ref = digest(&json!([self.state_ref, self.records]))?;
        Ok(())
    }
    pub(super) fn explain_lifecycle(
        &self,
        p: &ExplainParameters,
        cancelled: &AtomicBool,
    ) -> Result<Option<ExplanationPage>, QueryError> {
        check_cancelled(cancelled)?;
        let exact = self
            .records
            .iter()
            .filter(|r| lifecycle_kind(&r.kind) && r.id == p.selector)
            .collect::<Vec<_>>();
        let matched = if exact.is_empty() {
            self.records
                .iter()
                .filter(|r| r.kind == "retirement_evidence" && r.scope_ref == p.selector)
                .collect::<Vec<_>>()
        } else {
            exact
        };
        if matched.is_empty() {
            return Ok(None);
        }
        if matched.len() != 1 {
            return Err(QueryError::new(
                "AMBIGUOUS_SELECTOR",
                "multiple lifecycle comparisons match; use an exact retirement-record digest or qualified baseline:/retired:/exception: selector",
            ));
        }
        let record = matched[0];
        let scope = &record.scope_ref;
        let selected = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| lifecycle_kind(&r.kind) && r.scope_ref == *scope)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let description = json!({"governing_rule":"An original violation resolves only with sufficient comparable evidence of its original obligation.","rationale":"Absence, weaker policy, changed authority and lost coverage cannot prove a fix.","failure_prevented":"False baseline retirement, silent baseline growth and self-authorized exceptions.","evaluated_scope":scope,"recorded_result":record.value,"reporting_basis":"Current authored governance and supplied derived history are separate from current semantic evidence.","limitations":["Inspection neither authenticates a producer nor recreates an external grant.","A selected historical resolution is not evidence of the current repository.","Legacy entries without original anchors remain unresolved."],"remediation":"Retain original captured inputs, restore comparable authority/coverage and supply complete proof. Review protected maintenance through the existing AUTHORITY boundary."});
        Ok(Some(ExplanationPage {
            selector: p.selector.clone(),
            description,
            evidence: self.page(
                &selected,
                &p.page,
                &format!("lifecycle:{}", p.selector),
                cancelled,
            )?,
        }))
    }
}
