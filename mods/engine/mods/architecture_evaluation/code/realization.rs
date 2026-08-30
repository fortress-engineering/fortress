//! Reconciliation of observed implementation dependencies with CCG intent.

pub(crate) const REALIZATION_RULE_SOURCE: &str = include_str!("../data/realization_rule.json");

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::contract_coherency::ContractCoherencyGraph;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition, SourceSpan,
};
use crate::implementation_observation::{
    ObservationIssueKind, ObservationProvenance, ObservedImplementation, TargetClassification,
};

/// Stable identity of the observed architecture-realization rule.
pub const ARCH_REALIZATION_RULE_ID: &str = "ARCH-REALIZATION-001";

const REMEDIATION: &str = "Authorize a genuine direct dependency through an exact provider capability or refactor the source to use the declared facade/intermediary. Do not use transitive reachability as direct access permission.";

/// Deterministic observed-versus-declared relationship state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationState {
    /// Direct intent and direct implementation evidence agree.
    DeclaredAndObserved,
    /// Direct implementation evidence has no declared authorization path.
    ObservedUndeclared,
    /// Direct implementation access bypasses one or more declared intermediaries.
    ObservedTransitiveBypass,
    /// Direct intent has no corresponding supported Rust observation.
    DeclaredUnobserved,
    /// The observed dependency leaves the governed Module ecosystem.
    External,
    /// A supported Rust reference could not be resolved confidently.
    Unresolved,
}

/// One normalized reconciliation conclusion with exact context and evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ReconciliationRecord {
    state: ReconciliationState,
    source_module: String,
    target_module: Option<String>,
    external_target: Option<String>,
    declared_capabilities: Vec<String>,
    declared_path: Vec<String>,
    evidence: Vec<ObservationProvenance>,
}

impl ReconciliationRecord {
    /// Returns the deterministic relationship state.
    #[must_use]
    pub const fn state(&self) -> ReconciliationState {
        self.state
    }

    /// Returns the source Module identity.
    #[must_use]
    pub fn source_module(&self) -> &str {
        &self.source_module
    }

    /// Returns the governed target Module when applicable.
    #[must_use]
    pub fn target_module(&self) -> Option<&str> {
        self.target_module.as_deref()
    }

    /// Returns the external crate identity when applicable.
    #[must_use]
    pub fn external_target(&self) -> Option<&str> {
        self.external_target.as_deref()
    }

    /// Returns capabilities authorizing an exact direct dependency.
    #[must_use]
    pub fn declared_capabilities(&self) -> &[String] {
        &self.declared_capabilities
    }

    /// Returns the canonical CCG path when one exists.
    #[must_use]
    pub fn declared_path(&self) -> &[String] {
        &self.declared_path
    }

    /// Returns sorted source evidence supporting the observation.
    #[must_use]
    pub fn evidence(&self) -> &[ObservationProvenance] {
        &self.evidence
    }
}

/// Deterministic summary of every implemented reconciliation class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconciliationSummary {
    declared_direct: usize,
    observed_governed: usize,
    declared_and_observed: usize,
    observed_undeclared: usize,
    observed_transitive_bypass: usize,
    declared_unobserved: usize,
    external: usize,
    unresolved: usize,
    unsupported: usize,
    invalid: usize,
}

impl ReconciliationSummary {
    /// Returns declared direct Module dependency count.
    #[must_use]
    pub const fn declared_direct(self) -> usize {
        self.declared_direct
    }

    /// Returns normalized governed observed Module dependency count.
    #[must_use]
    pub const fn observed_governed(self) -> usize {
        self.observed_governed
    }

    /// Returns direct relationships present in intent and implementation.
    #[must_use]
    pub const fn declared_and_observed(self) -> usize {
        self.declared_and_observed
    }

    /// Returns unauthorized direct observations with no declared path.
    #[must_use]
    pub const fn observed_undeclared(self) -> usize {
        self.observed_undeclared
    }

    /// Returns direct observations authorized only transitively.
    #[must_use]
    pub const fn observed_transitive_bypass(self) -> usize {
        self.observed_transitive_bypass
    }

    /// Returns direct declared dependencies lacking supported observation.
    #[must_use]
    pub const fn declared_unobserved(self) -> usize {
        self.declared_unobserved
    }

    /// Returns normalized external observation count.
    #[must_use]
    pub const fn external(self) -> usize {
        self.external
    }

    /// Returns supported but unresolved observation count.
    #[must_use]
    pub const fn unresolved(self) -> usize {
        self.unresolved
    }

    /// Returns unsupported analyzer coverage issue count.
    #[must_use]
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    /// Returns invalid observed implementation issue count.
    #[must_use]
    pub const fn invalid(self) -> usize {
        self.invalid
    }
}

/// Complete architecture realization facts and normalized hard findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureRealization {
    records: Vec<ReconciliationRecord>,
    findings: Vec<CanonicalFinding>,
    summary: ReconciliationSummary,
    unsupported_semantics: Vec<String>,
}

impl ArchitectureRealization {
    /// Returns every reconciliation conclusion in canonical order.
    #[must_use]
    pub fn records(&self) -> &[ReconciliationRecord] {
        &self.records
    }

    /// Returns normalized hard architecture findings.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }

    /// Returns reconciliation counts.
    #[must_use]
    pub const fn summary(&self) -> ReconciliationSummary {
        self.summary
    }

    /// Returns semantic claims intentionally unsupported by v1.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[String] {
        &self.unsupported_semantics
    }
}

/// Reconciles independently observed direct Module edges with canonical CCG intent.
///
/// # Errors
///
/// Returns [`FindingError`] when hard violations cannot be normalized into the
/// shared canonical finding contract.
pub fn reconcile_implementation(
    ccg: &ContractCoherencyGraph,
    observed: &ObservedImplementation,
    standard_edition: &str,
) -> Result<ArchitectureRealization, FindingError> {
    let direct = declared_dependencies(ccg);
    let (mut records, observed_pairs) = governed_records(ccg, observed, &direct);
    records.extend(declared_unobserved_records(&direct, &observed_pairs));
    records.extend(coverage_records(observed));
    records.sort();
    records.dedup();
    let findings = hard_findings(&records, observed, standard_edition)?;
    let summary = summarize(&records, observed, direct.len());
    Ok(ArchitectureRealization {
        records,
        findings,
        summary,
        unsupported_semantics: vec![
            "capability_to_source_realization".into(),
            "macro_generated_dependency_semantics".into(),
            "external_dependency_governance".into(),
            "non_rust_implementation_dependencies".into(),
        ],
    })
}

type DeclaredDependencies = BTreeMap<(String, String), BTreeSet<String>>;

fn declared_dependencies(ccg: &ContractCoherencyGraph) -> DeclaredDependencies {
    let mut direct = DeclaredDependencies::new();
    for requirement in ccg.direct_requirements() {
        direct
            .entry((requirement.consumer().into(), requirement.provider().into()))
            .or_default()
            .insert(requirement.capability().into());
    }
    direct
}

fn governed_records(
    ccg: &ContractCoherencyGraph,
    observed: &ObservedImplementation,
    direct: &DeclaredDependencies,
) -> (Vec<ReconciliationRecord>, BTreeSet<(String, String)>) {
    let mut observed_pairs = BTreeSet::new();
    let mut records = Vec::new();
    for edge in observed.module_dependencies() {
        let key = (
            edge.source_module().to_owned(),
            edge.target_module().to_owned(),
        );
        observed_pairs.insert(key.clone());
        if let Some(capabilities) = direct.get(&key) {
            records.push(ReconciliationRecord {
                state: ReconciliationState::DeclaredAndObserved,
                source_module: key.0.clone(),
                target_module: Some(key.1.clone()),
                external_target: None,
                declared_capabilities: capabilities.iter().cloned().collect(),
                declared_path: vec![key.0, key.1],
                evidence: edge.evidence().to_vec(),
            });
        } else if let Some(path) = ccg.canonical_dependency_path(&key.0, &key.1) {
            records.push(ReconciliationRecord {
                state: ReconciliationState::ObservedTransitiveBypass,
                source_module: key.0,
                target_module: Some(key.1),
                external_target: None,
                declared_capabilities: Vec::new(),
                declared_path: path,
                evidence: edge.evidence().to_vec(),
            });
        } else {
            records.push(ReconciliationRecord {
                state: ReconciliationState::ObservedUndeclared,
                source_module: key.0,
                target_module: Some(key.1),
                external_target: None,
                declared_capabilities: Vec::new(),
                declared_path: Vec::new(),
                evidence: edge.evidence().to_vec(),
            });
        }
    }
    (records, observed_pairs)
}

fn declared_unobserved_records(
    direct: &DeclaredDependencies,
    observed_pairs: &BTreeSet<(String, String)>,
) -> Vec<ReconciliationRecord> {
    let mut records = Vec::new();
    for ((source, target), capabilities) in direct {
        if !observed_pairs.contains(&(source.clone(), target.clone())) {
            records.push(ReconciliationRecord {
                state: ReconciliationState::DeclaredUnobserved,
                source_module: source.clone(),
                target_module: Some(target.clone()),
                external_target: None,
                declared_capabilities: capabilities.iter().cloned().collect(),
                declared_path: vec![source.clone(), target.clone()],
                evidence: Vec::new(),
            });
        }
    }
    records
}

fn coverage_records(observed: &ObservedImplementation) -> Vec<ReconciliationRecord> {
    let mut external = BTreeMap::<(String, String), Vec<ObservationProvenance>>::new();
    let mut unresolved = BTreeMap::<(String, String), Vec<ObservationProvenance>>::new();
    for observation in observed.observations() {
        match observation.target_classification() {
            TargetClassification::ExternalDependency => {
                if let Some(target) = observation.external_target() {
                    external
                        .entry((observation.source_module().into(), target.into()))
                        .or_default()
                        .push(observation.provenance().clone());
                }
            }
            TargetClassification::Unresolved => {
                unresolved
                    .entry((
                        observation.source_module().into(),
                        observation.source_artifact().into(),
                    ))
                    .or_default()
                    .push(observation.provenance().clone());
            }
            TargetClassification::GovernedModule | TargetClassification::AnalysisTerritory => {}
        }
    }
    let mut records: Vec<ReconciliationRecord> = external
        .into_iter()
        .map(|((source, target), mut evidence)| {
            evidence.sort();
            evidence.dedup();
            ReconciliationRecord {
                state: ReconciliationState::External,
                source_module: source,
                target_module: None,
                external_target: Some(target),
                declared_capabilities: Vec::new(),
                declared_path: Vec::new(),
                evidence,
            }
        })
        .collect();
    records.extend(unresolved.into_iter().map(|((source, _), mut evidence)| {
        evidence.sort();
        evidence.dedup();
        ReconciliationRecord {
            state: ReconciliationState::Unresolved,
            source_module: source,
            target_module: None,
            external_target: None,
            declared_capabilities: Vec::new(),
            declared_path: Vec::new(),
            evidence,
        }
    }));
    records
}

fn hard_findings(
    records: &[ReconciliationRecord],
    observed: &ObservedImplementation,
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let mut findings = Vec::new();
    for record in records.iter().filter(|record| {
        matches!(
            record.state,
            ReconciliationState::ObservedUndeclared | ReconciliationState::ObservedTransitiveBypass
        )
    }) {
        findings.push(record_finding(record, standard_edition)?);
    }
    for issue in observed
        .issues()
        .iter()
        .filter(|issue| issue.kind() == ObservationIssueKind::Invalid)
    {
        findings.push(issue_finding(issue, standard_edition)?);
    }
    findings.sort();
    Ok(findings)
}

fn summarize(
    records: &[ReconciliationRecord],
    observed: &ObservedImplementation,
    declared_direct: usize,
) -> ReconciliationSummary {
    ReconciliationSummary {
        declared_direct,
        observed_governed: observed.module_dependencies().len(),
        declared_and_observed: count_state(records, ReconciliationState::DeclaredAndObserved),
        observed_undeclared: count_state(records, ReconciliationState::ObservedUndeclared),
        observed_transitive_bypass: count_state(
            records,
            ReconciliationState::ObservedTransitiveBypass,
        ),
        declared_unobserved: count_state(records, ReconciliationState::DeclaredUnobserved),
        external: count_state(records, ReconciliationState::External),
        unresolved: count_state(records, ReconciliationState::Unresolved),
        unsupported: observed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == ObservationIssueKind::Unsupported)
            .count(),
        invalid: observed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == ObservationIssueKind::Invalid)
            .count(),
    }
}

fn count_state(records: &[ReconciliationRecord], state: ReconciliationState) -> usize {
    records
        .iter()
        .filter(|record| record.state == state)
        .count()
}

fn record_finding(
    record: &ReconciliationRecord,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    let target = record.target_module.as_deref().unwrap_or("unresolved");
    let evidence = record.evidence.first();
    let location = evidence.map_or_else(
        || Ok(FindingLocation::none()),
        |evidence| {
            let position = evidence.location();
            let span = SourceSpan::new(
                position.line(),
                position.column(),
                position.line(),
                position.column(),
            )?;
            Ok(FindingLocation::at_path(evidence.source_path())?.with_span(span))
        },
    )?;
    let message = match record.state {
        ReconciliationState::ObservedUndeclared => format!(
            "Observed direct Rust dependency {} -> {target} has no direct CCG dependency authorization.",
            record.source_module
        ),
        ReconciliationState::ObservedTransitiveBypass => format!(
            "Observed direct Rust dependency {} -> {target} bypasses declared path {}; transitive reachability is not direct authorization.",
            record.source_module,
            record.declared_path.join(" -> ")
        ),
        _ => unreachable!("only hard reconciliation states produce findings"),
    };
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            ARCH_REALIZATION_RULE_ID,
            1,
            FindingCategory::Architecture,
            REMEDIATION,
        )?,
        FindingOccurrence::new(
            vec![record.source_module.clone(), target.into()],
            location,
            message,
        )?,
        EvaluatorProvenance::new(
            "fortress-core/architecture-realization",
            env!("CARGO_PKG_VERSION"),
        )?,
        standard_edition,
    )
}

fn issue_finding(
    issue: &crate::implementation_observation::ObservationIssue,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        RuleFindingDefinition::new(
            ARCH_REALIZATION_RULE_ID,
            1,
            FindingCategory::Architecture,
            REMEDIATION,
        )?,
        FindingOccurrence::new(
            Vec::new(),
            FindingLocation::at_path(issue.source_path())?,
            format!("Observed implementation is invalid: {}.", issue.detail()),
        )?,
        EvaluatorProvenance::new(
            "fortress-core/architecture-realization",
            env!("CARGO_PKG_VERSION"),
        )?,
        standard_edition,
    )
}
