//! Stable Fortress identity validation.
//!
//! This module implements draft rule `STD-ID-001`. It validates the canonical
//! serialized identity form without imposing a universal source-language casing
//! convention.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

const ENTITY_NAMESPACES: &[&str] = &[
    "ADR", "AF", "ARCH", "CAP", "CERT", "CHANGE", "CHG", "CHK", "CMD", "CONTRACT", "DEP", "DOC",
    "EX", "GUA", "INV", "ONBOARD", "PF", "PIPE", "REPO", "SEC", "SRC", "STD", "T", "TEST", "TF",
    "TRANS",
];

const RULE_NAMESPACES: &[&str] = &[
    "ARCH", "CERT", "CHANGE", "CONTRACT", "DEP", "DOC", "ONBOARD", "PIPE", "REPO", "SEC", "SRC",
    "STD", "TEST",
];

/// A validated Fortress entity identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StableId(Box<str>);

impl StableId {
    /// Parses and validates a Fortress stable entity identity.
    ///
    /// # Errors
    ///
    /// Returns [`StableIdError`] when the value has no registered namespace,
    /// lacks an identity segment, or contains a segment outside the uppercase
    /// ASCII alphanumeric grammar defined by `STD-ID-001`.
    pub fn parse(value: &str) -> Result<Self, StableIdError> {
        if value.is_empty() {
            return Err(StableIdError::Empty);
        }

        let mut segments = value.split('-');
        let namespace = segments.next().ok_or(StableIdError::Empty)?;

        if !ENTITY_NAMESPACES.contains(&namespace) {
            return Err(StableIdError::UnknownNamespace(namespace.into()));
        }

        let mut identity_segment_count = 0_usize;
        for (offset, segment) in segments.enumerate() {
            identity_segment_count += 1;
            if segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            {
                return Err(StableIdError::InvalidSegment {
                    index: offset + 1,
                    value: segment.into(),
                });
            }
        }

        if identity_segment_count == 0 {
            return Err(StableIdError::MissingIdentitySegment);
        }

        Ok(Self(value.into()))
    }

    /// Returns the canonical serialized identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the registered namespace segment.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.0
            .split_once('-')
            .map_or(self.as_str(), |(head, _)| head)
    }
}

impl Display for StableId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated Fortress standard rule identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RuleId(StableId);

impl RuleId {
    /// Parses a stable identity and verifies that it uses a rule namespace.
    ///
    /// # Errors
    ///
    /// Returns [`RuleIdError`] when the stable identity grammar fails or the
    /// namespace belongs to another Fortress entity class.
    pub fn parse(value: &str) -> Result<Self, RuleIdError> {
        let stable = StableId::parse(value).map_err(RuleIdError::InvalidStableId)?;
        if !RULE_NAMESPACES.contains(&stable.namespace()) {
            return Err(RuleIdError::NonRuleNamespace(stable.namespace().into()));
        }
        Ok(Self(stable))
    }

    /// Returns the canonical serialized rule identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for RuleId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

/// Explains why a value is not a valid Fortress stable identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StableIdError {
    /// The supplied value was empty.
    Empty,
    /// The first segment is not a registered Fortress namespace.
    UnknownNamespace(Box<str>),
    /// The namespace was not followed by an identity segment.
    MissingIdentitySegment,
    /// A segment was empty or contained a non-uppercase-ASCII-alphanumeric byte.
    InvalidSegment {
        /// Zero-based segment index in the complete identity.
        index: usize,
        /// Invalid segment content.
        value: Box<str>,
    },
}

impl StableIdError {
    /// Returns the governing Fortress rule identity for this finding.
    #[must_use]
    pub const fn rule_id(&self) -> &'static str {
        "STD-ID-001"
    }
}

impl Display for StableIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identity is empty"),
            Self::UnknownNamespace(namespace) => {
                write!(
                    formatter,
                    "identity namespace `{namespace}` is not registered"
                )
            }
            Self::MissingIdentitySegment => {
                formatter.write_str("identity has no segment after its namespace")
            }
            Self::InvalidSegment { index, value } => write!(
                formatter,
                "identity segment {index} (`{value}`) is not uppercase ASCII alphanumeric"
            ),
        }
    }
}

impl Error for StableIdError {}

/// Explains why a value is not a valid Fortress rule identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleIdError {
    /// The value failed the general stable identity grammar.
    InvalidStableId(StableIdError),
    /// The stable identity namespace does not identify a rule.
    NonRuleNamespace(Box<str>),
}

impl Display for RuleIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStableId(error) => Display::fmt(error, formatter),
            Self::NonRuleNamespace(namespace) => {
                write!(
                    formatter,
                    "identity namespace `{namespace}` is not a rule namespace"
                )
            }
        }
    }
}

impl Error for RuleIdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidStableId(error) => Some(error),
            Self::NonRuleNamespace(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleId, RuleIdError, StableId, StableIdError};

    /// `T-AF-STANDARD-REGISTRY-0001-R01-001`
    #[test]
    fn stable_identity_accepts_registered_nested_segments() {
        let identity = StableId::parse("T-TF-CLI-0001-R01-001");
        assert!(identity.is_ok());
    }

    /// `T-AF-STANDARD-REGISTRY-0001-R01-002`
    #[test]
    fn stable_identity_rejects_lowercase_segments() {
        let error = StableId::parse("arch-dependency-001");
        assert!(matches!(error, Err(StableIdError::UnknownNamespace(_))));
    }

    /// `T-AF-STANDARD-REGISTRY-0001-R01-003`
    #[test]
    fn rule_identity_rejects_entity_only_namespace() {
        let error = RuleId::parse("PF-PROJECT-0001");
        assert!(matches!(error, Err(RuleIdError::NonRuleNamespace(_))));
    }
}
