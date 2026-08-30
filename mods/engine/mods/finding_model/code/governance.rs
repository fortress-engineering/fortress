//! Authored finding baseline and exception authority plus deterministic lifecycle evaluation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::finding::{CanonicalFinding, FindingIdentityEligibility};
use crate::identity::{RuleId, StableId};

/// Canonical repository-relative location of finding governance authority.
pub const FINDING_GOVERNANCE_PATH: &str = "data/finding_governance.json";
/// Finding governance document schema identity.
pub const FINDING_GOVERNANCE_SCHEMA: &str = "urn:fortress:schema:v1:finding-governance";

/// Complete authored finding-governance authority for one project.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingGovernanceDocument {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    baseline: Option<FindingBaseline>,
    exceptions: Vec<FindingException>,
}

impl FindingGovernanceDocument {
    /// Creates empty canonical authority.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema: FINDING_GOVERNANCE_SCHEMA.into(),
            schema_version: 1,
            baseline: None,
            exceptions: Vec::new(),
        }
    }

    /// Parses and validates canonical authority.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON or invalid/deduplicated authority.
    pub fn from_json_str(source: &str) -> Result<Self, FindingGovernanceError> {
        let document: Self = serde_json::from_str(source).map_err(FindingGovernanceError::Json)?;
        document.validate()?;
        Ok(document)
    }

    /// Serializes deterministic canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if this validated document cannot be encoded.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string_pretty(self)?;
        output.push('\n');
        Ok(output)
    }

    /// Returns the active legacy baseline, if adoption established one.
    #[must_use]
    pub const fn baseline(&self) -> Option<&FindingBaseline> {
        self.baseline.as_ref()
    }

    /// Returns authored finding exceptions, including retired history.
    #[must_use]
    pub fn exceptions(&self) -> &[FindingException] {
        &self.exceptions
    }

    /// Creates a baseline from current eligible findings and refuses replacement.
    ///
    /// # Errors
    ///
    /// Returns an error when a baseline already exists.
    pub fn create_baseline(
        &mut self,
        standard_id: &str,
        standard_edition: &str,
        findings: &[CanonicalFinding],
    ) -> Result<BaselineMutationSummary, FindingGovernanceError> {
        if self.baseline.is_some() {
            return Err(FindingGovernanceError::BaselineAlreadyExists);
        }
        let mut active_entries = findings
            .iter()
            .filter(|finding| {
                finding.identity_eligibility() == FindingIdentityEligibility::Eligible
            })
            .map(BaselineEntry::from_finding)
            .collect::<Vec<_>>();
        active_entries.sort();
        active_entries.dedup_by(|left, right| left.finding_id == right.finding_id);
        let ineligible = findings.len() - active_entries.len();
        self.baseline = Some(FindingBaseline {
            standard_id: standard_id.into(),
            standard_edition: standard_edition.into(),
            active_entries,
            retired_entries: Vec::new(),
        });
        self.validate()?;
        Ok(BaselineMutationSummary {
            active: self
                .baseline
                .as_ref()
                .map_or(0, |value| value.active_entries.len()),
            removed: 0,
            ineligible,
        })
    }

    /// Removes resolved entries without ever adding current findings.
    ///
    /// # Errors
    ///
    /// Returns an error if no baseline exists or authority is invalid.
    pub fn prune_baseline(
        &mut self,
        findings: &[CanonicalFinding],
    ) -> Result<BaselineMutationSummary, FindingGovernanceError> {
        let baseline = self
            .baseline
            .as_mut()
            .ok_or(FindingGovernanceError::BaselineAbsent)?;
        let current = findings
            .iter()
            .map(CanonicalFinding::finding_id)
            .collect::<BTreeSet<_>>();
        let mut removed = Vec::new();
        baseline.active_entries.retain(|entry| {
            if current.contains(entry.finding_id.as_str()) {
                true
            } else {
                removed.push(RetiredBaselineEntry {
                    finding_id: entry.finding_id.clone(),
                    rule_id: entry.rule_id.clone(),
                });
                false
            }
        });
        baseline.retired_entries.extend(removed.iter().cloned());
        baseline.retired_entries.sort();
        baseline.retired_entries.dedup();
        let summary = BaselineMutationSummary {
            active: baseline.active_entries.len(),
            removed: removed.len(),
            ineligible: findings
                .iter()
                .filter(|finding| {
                    finding.identity_eligibility() == FindingIdentityEligibility::BaselineIneligible
                })
                .count(),
        };
        self.validate()?;
        Ok(summary)
    }

    /// Adds one explicit, active, finding-specific exception.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid fields, a missing target, or duplicate ID.
    pub fn create_exception(
        &mut self,
        exception_id: impl Into<String>,
        finding_id: &str,
        authority: impl Into<String>,
        rationale: impl Into<String>,
        findings: &[CanonicalFinding],
    ) -> Result<(), FindingGovernanceError> {
        let finding = findings
            .iter()
            .find(|finding| finding.finding_id() == finding_id)
            .ok_or_else(|| FindingGovernanceError::UnknownFinding(finding_id.into()))?;
        if finding.identity_eligibility() != FindingIdentityEligibility::Eligible {
            return Err(FindingGovernanceError::IneligibleFinding(finding_id.into()));
        }
        let exception = FindingException {
            id: exception_id.into(),
            finding_id: finding_id.into(),
            rule_id: finding.rule_id().into(),
            authority: authority.into(),
            rationale: rationale.into(),
            review_condition: None,
            state: ExceptionState::Active,
        };
        exception.validate()?;
        if self.exceptions.iter().any(|value| value.id == exception.id) {
            return Err(FindingGovernanceError::DuplicateException(
                exception.id.into(),
            ));
        }
        self.exceptions.push(exception);
        self.exceptions.sort();
        self.validate()
    }

    /// Retires an existing active exception while preserving reviewed history.
    ///
    /// # Errors
    ///
    /// Returns an error when the exception does not exist or is already retired.
    pub fn retire_exception(&mut self, id: &str) -> Result<(), FindingGovernanceError> {
        let exception = self
            .exceptions
            .iter_mut()
            .find(|exception| exception.id == id)
            .ok_or_else(|| FindingGovernanceError::UnknownException(id.into()))?;
        if exception.state == ExceptionState::Retired {
            return Err(FindingGovernanceError::ExceptionAlreadyRetired(id.into()));
        }
        exception.state = ExceptionState::Retired;
        Ok(())
    }

    fn validate(&self) -> Result<(), FindingGovernanceError> {
        if self.schema != FINDING_GOVERNANCE_SCHEMA || self.schema_version != 1 {
            return Err(FindingGovernanceError::UnsupportedSchema);
        }
        if let Some(baseline) = &self.baseline {
            validate_nonempty("baseline.standard_id", &baseline.standard_id)?;
            StableId::parse(&baseline.standard_id).map_err(|_| {
                FindingGovernanceError::InvalidStandard(baseline.standard_id.clone().into())
            })?;
            validate_nonempty("baseline.standard_edition", &baseline.standard_edition)?;
            if !is_strictly_sorted(&baseline.active_entries)
                || !is_strictly_sorted(&baseline.retired_entries)
            {
                return Err(FindingGovernanceError::NonCanonicalOrdering);
            }
            let mut ids = BTreeSet::new();
            for entry in &baseline.active_entries {
                entry.validate()?;
                if !ids.insert(entry.finding_id.as_str()) {
                    return Err(FindingGovernanceError::DuplicateFinding(
                        entry.finding_id.clone().into(),
                    ));
                }
            }
            for entry in &baseline.retired_entries {
                validate_digest(&entry.finding_id)?;
                RuleId::parse(&entry.rule_id).map_err(|_| {
                    FindingGovernanceError::InvalidRule(entry.rule_id.clone().into())
                })?;
                if !ids.insert(entry.finding_id.as_str()) {
                    return Err(FindingGovernanceError::DuplicateFinding(
                        entry.finding_id.clone().into(),
                    ));
                }
            }
        }
        let mut exception_ids = BTreeSet::new();
        if !is_strictly_sorted(&self.exceptions) {
            return Err(FindingGovernanceError::NonCanonicalOrdering);
        }
        for exception in &self.exceptions {
            exception.validate()?;
            if !exception_ids.insert(exception.id.as_str()) {
                return Err(FindingGovernanceError::DuplicateException(
                    exception.id.clone().into(),
                ));
            }
        }
        Ok(())
    }
}

/// Active legacy residue and retired identifiers that support reintroduction detection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingBaseline {
    standard_id: String,
    standard_edition: String,
    active_entries: Vec<BaselineEntry>,
    retired_entries: Vec<RetiredBaselineEntry>,
}

impl FindingBaseline {
    /// Returns the Standard identity used to create this baseline.
    #[must_use]
    pub fn standard_id(&self) -> &str {
        &self.standard_id
    }
    /// Returns the exact Standard edition used to create this baseline.
    #[must_use]
    pub fn standard_edition(&self) -> &str {
        &self.standard_edition
    }
    /// Returns active legacy entries.
    #[must_use]
    pub fn active_entries(&self) -> &[BaselineEntry] {
        &self.active_entries
    }
    /// Returns retired entries retained only to identify reintroduction.
    #[must_use]
    pub fn retired_entries(&self) -> &[RetiredBaselineEntry] {
        &self.retired_entries
    }
}

/// Minimal durable identity of one active legacy violation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    finding_id: String,
    rule_id: String,
    subjects: Vec<String>,
    violation_discriminator: String,
    rationale: Option<String>,
}

impl BaselineEntry {
    fn from_finding(finding: &CanonicalFinding) -> Self {
        Self {
            finding_id: finding.finding_id().into(),
            rule_id: finding.rule_id().into(),
            subjects: finding.entities().to_vec(),
            violation_discriminator: finding
                .violation_discriminator()
                .unwrap_or("VIOLATION")
                .into(),
            rationale: None,
        }
    }
    fn validate(&self) -> Result<(), FindingGovernanceError> {
        validate_digest(&self.finding_id)?;
        RuleId::parse(&self.rule_id)
            .map_err(|_| FindingGovernanceError::InvalidRule(self.rule_id.clone().into()))?;
        validate_nonempty(
            "baseline.violation_discriminator",
            &self.violation_discriminator,
        )?;
        for subject in &self.subjects {
            StableId::parse(subject)
                .map_err(|_| FindingGovernanceError::InvalidSubject(subject.clone().into()))?;
        }
        if self
            .rationale
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(FindingGovernanceError::EmptyField("baseline.rationale"));
        }
        Ok(())
    }
    /// Returns the stable finding identity.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
}

/// Historical identity of baseline residue removed by the monotonic ratchet.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredBaselineEntry {
    finding_id: String,
    rule_id: String,
}

/// Active or retired explicit exception authority.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingException {
    id: String,
    finding_id: String,
    rule_id: String,
    authority: String,
    rationale: String,
    review_condition: Option<String>,
    state: ExceptionState,
}

impl FindingException {
    fn validate(&self) -> Result<(), FindingGovernanceError> {
        let id = StableId::parse(&self.id)
            .map_err(|_| FindingGovernanceError::InvalidExceptionId(self.id.clone().into()))?;
        if id.namespace() != "EX" {
            return Err(FindingGovernanceError::InvalidExceptionId(
                self.id.clone().into(),
            ));
        }
        validate_digest(&self.finding_id)?;
        RuleId::parse(&self.rule_id)
            .map_err(|_| FindingGovernanceError::InvalidRule(self.rule_id.clone().into()))?;
        validate_nonempty("exception.authority", &self.authority)?;
        validate_nonempty("exception.rationale", &self.rationale)?;
        if self
            .review_condition
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(FindingGovernanceError::EmptyField(
                "exception.review_condition",
            ));
        }
        Ok(())
    }
    /// Returns the stable exception ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the target finding identity.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    /// Returns whether the exception currently affects enforcement.
    #[must_use]
    pub const fn state(&self) -> ExceptionState {
        self.state
    }
}

/// Exception lifecycle independent of the target violation lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExceptionState {
    /// Applies to current enforcement.
    Active,
    /// Preserved as reviewed history but no longer applies.
    Retired,
}

/// Lifecycle of one current raw finding relative to authored baseline history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingLifecycle {
    /// Not protected by active baseline residue.
    New,
    /// Matches active legacy residue.
    Baselined,
    /// Was pruned and has now returned.
    Reintroduced,
    /// Cannot safely participate in baseline matching.
    BaselineIneligible,
}

/// Explicit governance disposition independent of raw conformance and lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingDisposition {
    /// No explicit exception applies.
    None,
    /// An active authored exception applies.
    Excepted,
}

/// Whether one finding blocks progressive enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingEnforcement {
    /// Prevents progressive check success.
    Blocking,
    /// Remains a violation but does not block this change.
    NonBlocking,
}

/// Lifecycle and disposition projection for one raw current violation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GovernedFinding {
    finding_id: String,
    rule_id: String,
    raw_conformance: &'static str,
    lifecycle: FindingLifecycle,
    disposition: FindingDisposition,
    enforcement: FindingEnforcement,
    exception_ids: Vec<String>,
    reason: String,
}

impl GovernedFinding {
    /// Returns the stable finding identity.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }
    /// Returns the governing rule identity.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }
    /// Returns lifecycle relative to authored baseline history.
    #[must_use]
    pub const fn lifecycle(&self) -> FindingLifecycle {
        self.lifecycle
    }
    /// Returns explicit exception disposition.
    #[must_use]
    pub const fn disposition(&self) -> FindingDisposition {
        self.disposition
    }
    /// Returns progressive enforcement consequence.
    #[must_use]
    pub const fn enforcement(&self) -> FindingEnforcement {
        self.enforcement
    }
}

/// Deterministic summary of finding governance evaluation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FindingGovernanceSummary {
    /// New unexcepted findings.
    pub new_blocking: usize,
    /// Active legacy findings without an additional exception.
    pub baselined_non_blocking: usize,
    /// Current findings covered by active explicit exception authority.
    pub excepted_non_blocking: usize,
    /// Active baseline entries absent from current findings.
    pub resolved_baseline_entries: usize,
    /// Current findings lacking safe identity.
    pub baseline_ineligible: usize,
    /// Previously pruned findings that returned.
    pub reintroduced_blocking: usize,
}

/// Finding governance authority compatibility and enforcement projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FindingGovernanceEvaluation {
    authority: &'static str,
    enforcement: &'static str,
    findings: Vec<GovernedFinding>,
    resolved_baseline_entries: Vec<String>,
    unresolved_active_exceptions: Vec<String>,
    summary: FindingGovernanceSummary,
}

impl FindingGovernanceEvaluation {
    /// Returns whether progressive enforcement has no blocking finding or invalid authority.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.enforcement == "PASS"
    }
    /// Returns deterministic summary counts.
    #[must_use]
    pub const fn summary(&self) -> &FindingGovernanceSummary {
        &self.summary
    }
    /// Returns governed projections in raw finding order.
    #[must_use]
    pub fn findings(&self) -> &[GovernedFinding] {
        &self.findings
    }
    /// Returns active exceptions whose target finding is not current.
    #[must_use]
    pub fn unresolved_active_exceptions(&self) -> &[String] {
        &self.unresolved_active_exceptions
    }
}

/// Evaluates current findings against optional authored authority.
///
/// # Errors
///
/// Returns an error when a baseline was created under incompatible Standard authority
/// or duplicate stable finding identities disagree.
#[allow(clippy::too_many_lines)]
pub fn evaluate_finding_governance(
    findings: &[CanonicalFinding],
    authority: Option<&FindingGovernanceDocument>,
    standard_id: &str,
    standard_edition: &str,
) -> Result<FindingGovernanceEvaluation, FindingGovernanceError> {
    let mut current = BTreeMap::new();
    for finding in findings {
        if let Some(existing) = current.insert(finding.finding_id(), finding)
            && existing != finding
        {
            return Err(FindingGovernanceError::FindingIdentityCollision(
                finding.finding_id().into(),
            ));
        }
    }
    let baseline = authority.and_then(FindingGovernanceDocument::baseline);
    if let Some(baseline) = baseline {
        if baseline.standard_id != standard_id || baseline.standard_edition != standard_edition {
            return Err(FindingGovernanceError::IncompatibleBaseline {
                expected: format!("{standard_id}@{standard_edition}").into(),
                actual: format!("{}@{}", baseline.standard_id, baseline.standard_edition).into(),
            });
        }
        for entry in &baseline.active_entries {
            if let Some(finding) = current.get(entry.finding_id.as_str())
                && entry.rule_id != finding.rule_id()
            {
                return Err(FindingGovernanceError::AuthorityTargetMismatch(
                    entry.finding_id.clone().into(),
                ));
            }
        }
    }
    if let Some(document) = authority {
        for exception in document
            .exceptions
            .iter()
            .filter(|value| value.state == ExceptionState::Active)
        {
            if let Some(finding) = current.get(exception.finding_id.as_str())
                && exception.rule_id != finding.rule_id()
            {
                return Err(FindingGovernanceError::AuthorityTargetMismatch(
                    exception.finding_id.clone().into(),
                ));
            }
        }
    }
    let active = baseline.map_or_else(BTreeSet::new, |value| {
        value
            .active_entries
            .iter()
            .map(|entry| entry.finding_id.as_str())
            .collect()
    });
    let retired = baseline.map_or_else(BTreeSet::new, |value| {
        value
            .retired_entries
            .iter()
            .map(|entry| entry.finding_id.as_str())
            .collect()
    });
    let exceptions = authority.map_or_else(BTreeMap::new, |document| {
        let mut by_finding: BTreeMap<&str, Vec<&FindingException>> = BTreeMap::new();
        for exception in document
            .exceptions
            .iter()
            .filter(|value| value.state == ExceptionState::Active)
        {
            by_finding
                .entry(&exception.finding_id)
                .or_default()
                .push(exception);
        }
        by_finding
    });
    let mut summary = FindingGovernanceSummary::default();
    let mut governed = Vec::new();
    for finding in findings {
        let lifecycle =
            if finding.identity_eligibility() == FindingIdentityEligibility::BaselineIneligible {
                summary.baseline_ineligible += 1;
                FindingLifecycle::BaselineIneligible
            } else if active.contains(finding.finding_id()) {
                FindingLifecycle::Baselined
            } else if retired.contains(finding.finding_id()) {
                summary.reintroduced_blocking += 1;
                FindingLifecycle::Reintroduced
            } else {
                FindingLifecycle::New
            };
        let applied = exceptions
            .get(finding.finding_id())
            .cloned()
            .unwrap_or_default();
        let disposition = if applied.is_empty() {
            FindingDisposition::None
        } else {
            FindingDisposition::Excepted
        };
        let enforcement = if disposition == FindingDisposition::Excepted
            || lifecycle == FindingLifecycle::Baselined
        {
            FindingEnforcement::NonBlocking
        } else {
            FindingEnforcement::Blocking
        };
        match (lifecycle, disposition, enforcement) {
            (_, FindingDisposition::Excepted, FindingEnforcement::NonBlocking) => {
                summary.excepted_non_blocking += 1;
            }
            (FindingLifecycle::Baselined, _, FindingEnforcement::NonBlocking) => {
                summary.baselined_non_blocking += 1;
            }
            (
                FindingLifecycle::New | FindingLifecycle::BaselineIneligible,
                _,
                FindingEnforcement::Blocking,
            ) => summary.new_blocking += 1,
            _ => {}
        }
        governed.push(GovernedFinding {
            finding_id: finding.finding_id().into(),
            rule_id: finding.rule_id().into(),
            raw_conformance: "FAIL",
            lifecycle,
            disposition,
            enforcement,
            exception_ids: applied.iter().map(|value| value.id.clone()).collect(),
            reason: match (lifecycle, disposition) {
                (_, FindingDisposition::Excepted) => "active explicit exception authority".into(),
                (FindingLifecycle::Baselined, _) => "active legacy baseline residue".into(),
                (FindingLifecycle::Reintroduced, _) => {
                    "retired baseline violation reintroduced".into()
                }
                (FindingLifecycle::BaselineIneligible, _) => {
                    "stable semantic identity unavailable".into()
                }
                (FindingLifecycle::New, _) => "not present in active baseline".into(),
            },
        });
    }
    let current_ids = current.keys().copied().collect::<BTreeSet<_>>();
    let resolved_baseline_entries = baseline.map_or_else(Vec::new, |value| {
        value
            .active_entries
            .iter()
            .filter(|entry| !current_ids.contains(entry.finding_id.as_str()))
            .map(|entry| entry.finding_id.clone())
            .collect()
    });
    summary.resolved_baseline_entries = resolved_baseline_entries.len();
    let unresolved_active_exceptions = authority.map_or_else(Vec::new, |document| {
        document
            .exceptions
            .iter()
            .filter(|exception| {
                exception.state == ExceptionState::Active
                    && !current_ids.contains(exception.finding_id.as_str())
            })
            .map(|exception| exception.id.clone())
            .collect()
    });
    let success = governed
        .iter()
        .all(|value| value.enforcement == FindingEnforcement::NonBlocking);
    Ok(FindingGovernanceEvaluation {
        authority: if authority.is_some() {
            "VALID"
        } else {
            "ABSENT"
        },
        enforcement: if success { "PASS" } else { "BLOCKED" },
        findings: governed,
        resolved_baseline_entries,
        unresolved_active_exceptions,
        summary,
    })
}

/// Baseline mutation counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BaselineMutationSummary {
    /// Remaining active entries.
    pub active: usize,
    /// Entries removed by this prune.
    pub removed: usize,
    /// Current findings that could not be baselined.
    pub ineligible: usize,
}

/// Finding governance validation or mutation failure.
#[derive(Debug)]
pub enum FindingGovernanceError {
    /// JSON syntax or typed shape was invalid.
    Json(serde_json::Error),
    /// Schema identity/version is unsupported.
    UnsupportedSchema,
    /// A required field was empty.
    EmptyField(&'static str),
    /// A finding digest was malformed.
    InvalidFindingId(Box<str>),
    /// A rule identity was malformed.
    InvalidRule(Box<str>),
    /// Standard identity was malformed.
    InvalidStandard(Box<str>),
    /// Baseline subject identity was malformed.
    InvalidSubject(Box<str>),
    /// Exception identity was malformed or used another namespace.
    InvalidExceptionId(Box<str>),
    /// Finding identity occurred more than once in baseline history.
    DuplicateFinding(Box<str>),
    /// Exception identity occurred more than once.
    DuplicateException(Box<str>),
    /// Authored arrays were not in canonical strict order.
    NonCanonicalOrdering,
    /// Authored rule metadata disagreed with its stable finding target.
    AuthorityTargetMismatch(Box<str>),
    /// A stable finding ID referred to conflicting semantic findings.
    FindingIdentityCollision(Box<str>),
    /// Baseline already exists and cannot be silently overwritten.
    BaselineAlreadyExists,
    /// Prune was requested without a baseline.
    BaselineAbsent,
    /// Baseline Standard authority does not match current semantics.
    IncompatibleBaseline {
        /// Required current authority.
        expected: Box<str>,
        /// Authored baseline authority.
        actual: Box<str>,
    },
    /// Exception target is not a current finding.
    UnknownFinding(Box<str>),
    /// Exception target cannot be stably governed.
    IneligibleFinding(Box<str>),
    /// Exception does not exist.
    UnknownException(Box<str>),
    /// Exception was already retired.
    ExceptionAlreadyRetired(Box<str>),
}

impl Display for FindingGovernanceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "finding governance JSON is invalid: {error}"),
            Self::UnsupportedSchema => write!(
                formatter,
                "finding governance schema/version is unsupported"
            ),
            Self::EmptyField(field) => {
                write!(formatter, "finding governance field `{field}` is empty")
            }
            Self::InvalidFindingId(value) => write!(formatter, "finding ID `{value}` is invalid"),
            Self::InvalidRule(value) => write!(formatter, "rule ID `{value}` is invalid"),
            Self::InvalidStandard(value) => write!(formatter, "Standard ID `{value}` is invalid"),
            Self::InvalidSubject(value) => {
                write!(formatter, "finding subject `{value}` is invalid")
            }
            Self::InvalidExceptionId(value) => {
                write!(formatter, "exception ID `{value}` is invalid")
            }
            Self::DuplicateFinding(value) => write!(
                formatter,
                "finding ID `{value}` is duplicated in baseline history"
            ),
            Self::DuplicateException(value) => {
                write!(formatter, "exception ID `{value}` is duplicated")
            }
            Self::NonCanonicalOrdering => {
                write!(
                    formatter,
                    "finding governance arrays are not canonically ordered"
                )
            }
            Self::AuthorityTargetMismatch(value) => write!(
                formatter,
                "finding governance metadata disagrees with target `{value}`"
            ),
            Self::FindingIdentityCollision(value) => write!(
                formatter,
                "stable finding ID `{value}` identifies disagreeing violations"
            ),
            Self::BaselineAlreadyExists => write!(
                formatter,
                "finding baseline already exists; prune it instead of replacing it"
            ),
            Self::BaselineAbsent => write!(formatter, "finding baseline is absent"),
            Self::IncompatibleBaseline { expected, actual } => write!(
                formatter,
                "finding baseline authority `{actual}` is incompatible with current `{expected}`"
            ),
            Self::UnknownFinding(value) => write!(
                formatter,
                "finding `{value}` does not exist in the current audit"
            ),
            Self::IneligibleFinding(value) => write!(
                formatter,
                "finding `{value}` lacks safe baseline/exception identity"
            ),
            Self::UnknownException(value) => {
                write!(formatter, "exception `{value}` does not exist")
            }
            Self::ExceptionAlreadyRetired(value) => {
                write!(formatter, "exception `{value}` is already retired")
            }
        }
    }
}

impl Error for FindingGovernanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), FindingGovernanceError> {
    if value.trim().is_empty() {
        Err(FindingGovernanceError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), FindingGovernanceError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(FindingGovernanceError::InvalidFindingId(value.into()));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(FindingGovernanceError::InvalidFindingId(value.into()))
    }
}

fn is_strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
