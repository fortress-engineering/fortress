//! Canonical normalized findings for Snapshot Governance rules.
//!
//! Findings are derived evidence about one evaluated snapshot. They preserve
//! governing rule identity and evaluator provenance without redefining either
//! normative rule meaning or future certification state.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::identity::{RuleId, RuleIdError, StableId, StableIdError};

pub use crate::standard::FindingCategory;

/// Implemented semantic state of a normalized snapshot finding.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingState {
    /// The evaluated snapshot violates the governing rule.
    Fail,
}

/// Whether a finding has enough semantic authority for lifecycle governance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingIdentityEligibility {
    /// The identifier is stable across irrelevant presentation and location drift.
    Eligible,
    /// No safe semantic or repository-relative subject identity was available.
    BaselineIneligible,
}

/// One-based inclusive source range when an evaluator knows exact location.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SourceSpan {
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

impl SourceSpan {
    /// Creates a non-empty, ordered, one-based source range.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::InvalidSourceSpan`] for zero coordinates or an
    /// end position that precedes the start position.
    pub fn new(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> Result<Self, FindingError> {
        let start = (start_line, start_column);
        let end = (end_line, end_column);
        if start_line == 0 || start_column == 0 || end_line == 0 || end_column == 0 || end < start {
            return Err(FindingError::InvalidSourceSpan {
                start_line,
                start_column,
                end_line,
                end_column,
            });
        }
        Ok(Self {
            start_line,
            start_column,
            end_line,
            end_column,
        })
    }
}

/// Optional repository/source location associated with a finding.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FindingLocation {
    path: Option<String>,
    span: Option<SourceSpan>,
    symbol: Option<String>,
}

impl FindingLocation {
    /// Creates an entity- or repository-level location with no path or span.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            path: None,
            span: None,
            symbol: None,
        }
    }

    /// Creates a canonical repository-relative path location.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::InvalidPath`] when the path is empty, absolute,
    /// dot-relative, parent-relative, or contains a backslash.
    pub fn at_path(path: impl Into<String>) -> Result<Self, FindingError> {
        let path = path.into();
        if !is_canonical_relative_path(&path) {
            return Err(FindingError::InvalidPath(path.into()));
        }
        Ok(Self {
            path: Some(path),
            span: None,
            symbol: None,
        })
    }

    /// Adds an exact source range to this location.
    #[must_use]
    pub const fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
        self
    }

    /// Adds a non-empty analyzer-reported symbol identity.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::EmptyField`] for an empty symbol.
    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Result<Self, FindingError> {
        let symbol = symbol.into();
        if symbol.is_empty() {
            return Err(FindingError::EmptyField("location.symbol"));
        }
        self.symbol = Some(symbol);
        Ok(self)
    }

    /// Returns the repository-relative path when one is known.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the analyzer-reported semantic symbol when one is known.
    #[must_use]
    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }
}

/// Normative metadata needed to normalize a rule violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleFindingDefinition {
    rule_id: String,
    integrity_tier: u8,
    category: FindingCategory,
    remediation: String,
}

impl RuleFindingDefinition {
    /// Creates validated rule metadata for normalized findings.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError`] for an invalid rule identity, tier above four,
    /// or empty remediation.
    pub fn new(
        rule_id: impl Into<String>,
        integrity_tier: u8,
        category: FindingCategory,
        remediation: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let rule_id = rule_id.into();
        RuleId::parse(&rule_id).map_err(FindingError::InvalidRuleId)?;
        if integrity_tier > 4 {
            return Err(FindingError::InvalidIntegrityTier(integrity_tier));
        }
        let remediation = remediation.into();
        if remediation.is_empty() {
            return Err(FindingError::EmptyField("remediation"));
        }
        Ok(Self {
            rule_id,
            integrity_tier,
            category,
            remediation,
        })
    }
}

/// Snapshot-specific occurrence data supplied by one evaluator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingOccurrence {
    entities: Vec<String>,
    location: FindingLocation,
    violation_discriminator: Option<String>,
    message: String,
}

impl FindingOccurrence {
    /// Creates one validated rule violation occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError`] for an invalid affected entity identity or an
    /// empty deterministic message.
    pub fn new(
        entities: Vec<String>,
        location: FindingLocation,
        message: impl Into<String>,
    ) -> Result<Self, FindingError> {
        for entity in &entities {
            StableId::parse(entity).map_err(|source| FindingError::InvalidEntity {
                value: entity.clone().into(),
                source,
            })?;
        }
        let message = message.into();
        if message.is_empty() {
            return Err(FindingError::EmptyField("message"));
        }
        Ok(Self {
            entities,
            location,
            violation_discriminator: None,
            message,
        })
    }

    /// Adds a stable evaluator-defined violation discriminator.
    ///
    /// A discriminator identifies the violated relationship or condition; it
    /// must not contain presentation wording or a source coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::InvalidDiscriminator`] for an empty or
    /// non-canonical value.
    pub fn with_discriminator(
        mut self,
        discriminator: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let discriminator = discriminator.into();
        if discriminator.is_empty()
            || discriminator.contains(char::is_whitespace)
            || discriminator.contains('\\')
        {
            return Err(FindingError::InvalidDiscriminator(discriminator.into()));
        }
        self.violation_discriminator = Some(discriminator);
        Ok(self)
    }
}

/// Analyzer or native evaluator identity participating in finding provenance.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EvaluatorProvenance {
    id: String,
    version: String,
}

impl EvaluatorProvenance {
    /// Creates non-empty evaluator provenance.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError::EmptyField`] when either identity field is empty.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Result<Self, FindingError> {
        let id = id.into();
        let version = version.into();
        if id.is_empty() {
            return Err(FindingError::EmptyField("evaluator.id"));
        }
        if version.is_empty() {
            return Err(FindingError::EmptyField("evaluator.version"));
        }
        Ok(Self { id, version })
    }
}

/// Content-addressed normalized evidence of one snapshot rule violation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalFinding {
    finding_id: String,
    identity_eligibility: FindingIdentityEligibility,
    violation_discriminator: Option<String>,
    rule_id: String,
    integrity_tier: u8,
    category: FindingCategory,
    state: FindingState,
    entities: Vec<String>,
    location: FindingLocation,
    message: String,
    remediation: String,
    evaluator: EvaluatorProvenance,
    standard_edition: String,
}

impl CanonicalFinding {
    /// Normalizes and fingerprints one evaluated violation.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError`] for an empty standard edition or canonical
    /// serialization failure.
    pub fn failure(
        definition: RuleFindingDefinition,
        occurrence: FindingOccurrence,
        evaluator: EvaluatorProvenance,
        standard_edition: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let standard_edition = standard_edition.into();
        if standard_edition.is_empty() {
            return Err(FindingError::EmptyField("standard_edition"));
        }
        let state = FindingState::Fail;
        let stable_subject = stable_subject(&occurrence);
        let violation_discriminator = occurrence.violation_discriminator.clone().or_else(|| {
            if occurrence.entities.is_empty() {
                occurrence
                    .location
                    .symbol()
                    .map(|value| format!("SYMBOL:{value}"))
                    .or_else(|| {
                        occurrence
                            .location
                            .path()
                            .map(|value| format!("PATH:{value}"))
                    })
            } else {
                Some("VIOLATION".into())
            }
        });
        let identity_eligibility = if stable_subject.is_some() {
            FindingIdentityEligibility::Eligible
        } else {
            FindingIdentityEligibility::BaselineIneligible
        };
        let material = FindingIdentityMaterial {
            rule_id: &definition.rule_id,
            stable_subject,
            violation_discriminator: violation_discriminator.as_deref(),
        };
        let serialized = serde_json::to_vec(&material).map_err(FindingError::Serialization)?;
        let finding_id = if identity_eligibility == FindingIdentityEligibility::Eligible {
            format!("sha256:{:x}", Sha256::digest(serialized))
        } else {
            let fallback = IneligibleIdentityMaterial {
                rule_id: &definition.rule_id,
                entities: &occurrence.entities,
                location: &occurrence.location,
                message: &occurrence.message,
            };
            let serialized = serde_json::to_vec(&fallback).map_err(FindingError::Serialization)?;
            format!("sha256:{:x}", Sha256::digest(serialized))
        };

        Ok(Self {
            finding_id,
            identity_eligibility,
            violation_discriminator,
            rule_id: definition.rule_id,
            integrity_tier: definition.integrity_tier,
            category: definition.category,
            state,
            entities: occurrence.entities,
            location: occurrence.location,
            message: occurrence.message,
            remediation: definition.remediation,
            evaluator,
            standard_edition,
        })
    }

    /// Returns the stable finding identity, or an occurrence identity when the
    /// finding is explicitly baseline-ineligible.
    #[must_use]
    pub fn finding_fingerprint(&self) -> &str {
        &self.finding_id
    }

    /// Returns the finding identity.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    /// Returns whether this finding may safely participate in a baseline.
    #[must_use]
    pub const fn identity_eligibility(&self) -> FindingIdentityEligibility {
        self.identity_eligibility
    }

    /// Returns the stable violated-condition discriminator when available.
    #[must_use]
    pub fn violation_discriminator(&self) -> Option<&str> {
        self.violation_discriminator.as_deref()
    }

    /// Returns the stable governing rule identity.
    #[must_use]
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the rule integrity tier.
    #[must_use]
    pub const fn integrity_tier(&self) -> u8 {
        self.integrity_tier
    }

    /// Returns the rule category.
    #[must_use]
    pub const fn category(&self) -> FindingCategory {
        self.category
    }

    /// Returns the implemented violation state.
    #[must_use]
    pub const fn state(&self) -> FindingState {
        self.state
    }

    /// Returns affected project entity identities in evaluator-defined order.
    #[must_use]
    pub fn entities(&self) -> &[String] {
        &self.entities
    }

    /// Returns the optional repository/source location.
    #[must_use]
    pub const fn location(&self) -> &FindingLocation {
        &self.location
    }

    /// Returns the deterministic human-readable violation message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns governed remediation guidance.
    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Returns the exact standard edition used during evaluation.
    #[must_use]
    pub fn standard_edition(&self) -> &str {
        &self.standard_edition
    }
}

impl Ord for CanonicalFinding {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rule_id
            .cmp(&other.rule_id)
            .then_with(|| self.location.cmp(&other.location))
            .then_with(|| self.entities.cmp(&other.entities))
            .then_with(|| self.message.cmp(&other.message))
            .then_with(|| self.integrity_tier.cmp(&other.integrity_tier))
            .then_with(|| self.category.cmp(&other.category))
            .then_with(|| self.state.cmp(&other.state))
            .then_with(|| self.evaluator.cmp(&other.evaluator))
            .then_with(|| self.standard_edition.cmp(&other.standard_edition))
            .then_with(|| self.identity_eligibility.cmp(&other.identity_eligibility))
            .then_with(|| {
                self.violation_discriminator
                    .cmp(&other.violation_discriminator)
            })
            .then_with(|| self.finding_id.cmp(&other.finding_id))
    }
}

impl PartialOrd for CanonicalFinding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Explains invalid canonical finding input or serialization.
#[derive(Debug)]
pub enum FindingError {
    /// The governing rule identity was invalid.
    InvalidRuleId(RuleIdError),
    /// The integrity tier exceeded the zero-through-four range.
    InvalidIntegrityTier(u8),
    /// An affected project entity identity was invalid.
    InvalidEntity {
        /// Invalid entity value.
        value: Box<str>,
        /// Stable identity validation failure.
        source: StableIdError,
    },
    /// A violation discriminator was not stable canonical material.
    InvalidDiscriminator(Box<str>),
    /// A required string field was empty.
    EmptyField(&'static str),
    /// A repository path was not canonical and relative.
    InvalidPath(Box<str>),
    /// A source range used zero coordinates or reversed ordering.
    InvalidSourceSpan {
        /// Starting one-based line.
        start_line: u32,
        /// Starting one-based column.
        start_column: u32,
        /// Ending one-based line.
        end_line: u32,
        /// Ending one-based column.
        end_column: u32,
    },
    /// Canonical finding material could not be serialized.
    Serialization(serde_json::Error),
}

impl Display for FindingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRuleId(error) => write!(formatter, "invalid finding rule ID: {error}"),
            Self::InvalidIntegrityTier(tier) => {
                write!(formatter, "finding integrity tier {tier} exceeds four")
            }
            Self::InvalidEntity { value, source } => {
                write!(formatter, "invalid finding entity `{value}`: {source}")
            }
            Self::InvalidDiscriminator(value) => {
                write!(
                    formatter,
                    "finding discriminator `{value}` is not canonical"
                )
            }
            Self::EmptyField(field) => write!(formatter, "finding field `{field}` is empty"),
            Self::InvalidPath(path) => {
                write!(
                    formatter,
                    "finding path `{path}` is not canonical and relative"
                )
            }
            Self::InvalidSourceSpan {
                start_line,
                start_column,
                end_line,
                end_column,
            } => write!(
                formatter,
                "finding span {start_line}:{start_column}-{end_line}:{end_column} is invalid"
            ),
            Self::Serialization(error) => {
                write!(formatter, "canonical finding serialization failed: {error}")
            }
        }
    }
}

impl Error for FindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRuleId(error) => Some(error),
            Self::InvalidEntity { source, .. } => Some(source),
            Self::Serialization(error) => Some(error),
            Self::InvalidIntegrityTier(_)
            | Self::EmptyField(_)
            | Self::InvalidDiscriminator(_)
            | Self::InvalidPath(_)
            | Self::InvalidSourceSpan { .. } => None,
        }
    }
}

#[derive(Serialize)]
struct FindingIdentityMaterial<'a> {
    rule_id: &'a str,
    stable_subject: Option<StableFindingSubject<'a>>,
    violation_discriminator: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
enum StableFindingSubject<'a> {
    Entities(&'a [String]),
    Symbol(&'a str),
    RepositoryPath(&'a str),
}

#[derive(Serialize)]
struct IneligibleIdentityMaterial<'a> {
    rule_id: &'a str,
    entities: &'a [String],
    location: &'a FindingLocation,
    message: &'a str,
}

fn stable_subject(occurrence: &FindingOccurrence) -> Option<StableFindingSubject<'_>> {
    if !occurrence.entities.is_empty() {
        Some(StableFindingSubject::Entities(&occurrence.entities))
    } else if let Some(symbol) = occurrence.location.symbol() {
        Some(StableFindingSubject::Symbol(symbol))
    } else {
        occurrence
            .location
            .path()
            .map(StableFindingSubject::RepositoryPath)
    }
}

fn is_canonical_relative_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_path = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !value.is_empty()
        && !drive_path
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
