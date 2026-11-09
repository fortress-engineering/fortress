//! Immutable decision explanations reuse existing bounded paging and RPC envelopes.
use super::{
    ExplainParameters, ExplanationPage, QueryError, QueryService, check_cancelled, digest,
};
use crate::development_governance::ChangeDecision;
use serde_json::json;
use std::sync::atomic::AtomicBool;
impl QueryService {
    /// Attaches previously evaluated decisions. No authorization or analysis is initiated.
    /// Serialized receipts remain provenance; this method cannot reconstruct grants.
    /// # Errors
    /// Refuses malformed decisions, conflicting identities and existing index limits.
    pub fn with_change_decisions(
        mut self,
        mut decisions: Vec<ChangeDecision>,
    ) -> Result<Self, QueryError> {
        if decisions.is_empty() {
            return Ok(self);
        }
        if decisions.len() > 16 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "at most sixteen prepared decisions",
            ));
        }
        decisions.sort_by(|a, b| a.proposal_ref.cmp(&b.proposal_ref));
        for decision in decisions {
            let id = decision
                .digest()
                .map_err(|e| QueryError::new(&e.code, e.message))?;
            if self
                .records
                .iter()
                .any(|r| r.id == id || r.scope_ref == decision.proposal_ref)
            {
                return Err(QueryError::new(
                    "AMBIGUOUS_AUTHORITY",
                    "decision already attached",
                ));
            }
            let scope = decision.proposal_ref.clone();
            self.add_record("change_decision",&id,&scope,json!({"id":id,"proposal_ref":scope,"disposition":decision.disposition,"semantic_enforcement":decision.semantic_enforcement,"assurance_requirements":decision.assurance_requirements,"protected_authority":decision.protected_authority,"host_coverage":decision.host_coverage,"enforced":decision.enforced,"base_state_ref":decision.base_state_ref,"candidate_state_ref":decision.candidate_state_ref,"candidate_binding":decision.candidate_binding,"base_authority_ref":decision.base_authority_ref,"policy_ref":decision.policy_ref,"weakening_preserved":decision.transition.weakenings,"receipt_semantics":decision.receipt_semantics,"authorization_references":decision.authorization_references,"inspection_authenticity":"NOT_REVERIFIED_PROVENANCE"}))?;
            for (requirement, outcome) in decision.requirements.iter().zip(&decision.authorization)
            {
                self.add_record(
                    "authorization_requirement",
                    &requirement.id,
                    &scope,
                    json!({"requirement":requirement,"recorded_verification":outcome,"inspection_authenticity":"NOT_REVERIFIED_PROVENANCE"}),
                )?;
            }
        }
        self.records
            .sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        self.state_ref = digest(&json!([self.state_ref, self.records]))?;
        Ok(self)
    }
    pub(super) fn explain_change_decision(
        &self,
        p: &ExplainParameters,
        cancelled: &AtomicBool,
    ) -> Result<Option<ExplanationPage>, QueryError> {
        check_cancelled(cancelled)?;
        let Some(record) = self.records.iter().find(|r| {
            matches!(
                r.kind.as_str(),
                "change_decision" | "authorization_requirement"
            ) && r.id == p.selector
        }) else {
            return Ok(None);
        };
        let scope = &record.scope_ref;
        let selected = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r.scope_ref == *scope
                    && matches!(
                        r.kind.as_str(),
                        "change_decision" | "authorization_requirement"
                    )
            })
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let description = json!({"governing_rule":"Trusted original base selection; candidate text cannot authorize its own authority changes.","rationale":"Separate permission from semantic correctness, assurance, source integrity and provider authentication.","failure_prevented":"Candidate self-authorization and replay against another proposal or scope.","evaluated_scope":scope,"verification_basis":"Recorded provenance only; external checks and host protection claimed by a serialized receipt are not independently reverified by this query.","provenance":record.value,"limitations":["Serialized receipts do not recreate validated grants.","Provider protection is unverified unless independently established by a trusted host."],"remediation":"Supply independently authenticated exact-proposal authorization through a trusted host; proposals and citations remain unapproved."});
        Ok(Some(ExplanationPage {
            selector: p.selector.clone(),
            description,
            evidence: self.page(
                &selected,
                &p.page,
                &format!("authority:{}", p.selector),
                cancelled,
            )?,
        }))
    }
}
