//! Fortress Engineering Standard registry primitives.
//!
//! The registry exposes stable rule metadata independently from repository
//! observation, execution, certification, and presentation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::identity::{RuleId, RuleIdError};

const DRAFT_RULES: &[RuleDescriptor] = &[
    RuleDescriptor {
        id: "STD-ID-001",
        title: "Stable serialized identity",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
    RuleDescriptor {
        id: "ARCH-DEPENDENCY-001",
        title: "Acyclic declared component dependencies",
        status: RuleStatus::Draft,
        integrity_tier: 1,
    },
];

/// Release state of a rule exposed by a standard registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleStatus {
    /// The rule is mutable pre-release work and cannot support a stable claim.
    Draft,
    /// The rule is a release candidate awaiting final gates and authorization.
    Candidate,
    /// The rule belongs to an immutable released standard edition.
    Released,
    /// The rule remains addressable for history but is no longer active.
    Retired,
}

/// Minimal discoverable metadata for a Fortress rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleDescriptor {
    id: &'static str,
    title: &'static str,
    status: RuleStatus,
    integrity_tier: u8,
}

impl RuleDescriptor {
    /// Returns the stable public rule identity.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Returns the human-readable rule title.
    #[must_use]
    pub const fn title(&self) -> &'static str {
        self.title
    }

    /// Returns the rule release state.
    #[must_use]
    pub const fn status(&self) -> RuleStatus {
        self.status
    }

    /// Returns the rule integrity tier from zero through four.
    #[must_use]
    pub const fn integrity_tier(&self) -> u8 {
        self.integrity_tier
    }
}

/// Read-only registry for one precise Fortress Engineering Standard identity.
#[derive(Clone, Copy, Debug)]
pub struct StandardRegistry {
    edition: &'static str,
    status: RuleStatus,
    rules: &'static [RuleDescriptor],
}

impl StandardRegistry {
    /// Returns the initial draft path toward Fortress Engineering Standard
    /// 1.0.0.
    #[must_use]
    pub const fn draft_1_0() -> Self {
        Self {
            edition: "1.0.0-draft.1",
            status: RuleStatus::Draft,
            rules: DRAFT_RULES,
        }
    }

    /// Returns the exact standard edition identity.
    #[must_use]
    pub const fn edition(&self) -> &'static str {
        self.edition
    }

    /// Returns the standard bundle status.
    #[must_use]
    pub const fn status(&self) -> RuleStatus {
        self.status
    }

    /// Iterates through registered rules in canonical manifest order.
    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &RuleDescriptor> {
        self.rules.iter()
    }

    /// Finds a registered rule by exact stable identity.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&RuleDescriptor> {
        self.rules.iter().find(|rule| rule.id == id)
    }

    /// Validates registered rule identities, uniqueness, and integrity tiers.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] for an invalid ID, duplicate ID, or tier
    /// outside the zero-through-four range.
    pub fn validate(&self) -> Result<(), RegistryError> {
        for (index, rule) in self.rules.iter().enumerate() {
            RuleId::parse(rule.id).map_err(|source| RegistryError::InvalidRuleId {
                id: rule.id,
                source,
            })?;

            if rule.integrity_tier > 4 {
                return Err(RegistryError::InvalidIntegrityTier {
                    id: rule.id,
                    tier: rule.integrity_tier,
                });
            }

            if self.rules[..index]
                .iter()
                .any(|existing| existing.id == rule.id)
            {
                return Err(RegistryError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }
}

/// Explains why a standard registry is structurally invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A rule does not have a valid stable rule identity.
    InvalidRuleId {
        /// Invalid rule value.
        id: &'static str,
        /// Identity validation failure.
        source: RuleIdError,
    },
    /// A stable rule identity appears more than once.
    DuplicateRuleId(&'static str),
    /// A rule declared an integrity tier outside zero through four.
    InvalidIntegrityTier {
        /// Invalid rule identity.
        id: &'static str,
        /// Invalid tier value.
        tier: u8,
    },
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRuleId { id, source } => {
                write!(
                    formatter,
                    "registered rule `{id}` has an invalid identity: {source}"
                )
            }
            Self::DuplicateRuleId(id) => write!(formatter, "rule identity `{id}` is duplicated"),
            Self::InvalidIntegrityTier { id, tier } => {
                write!(formatter, "rule `{id}` has invalid integrity tier {tier}")
            }
        }
    }
}

impl Error for RegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRuleId { source, .. } => Some(source),
            Self::DuplicateRuleId(_) | Self::InvalidIntegrityTier { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuleStatus, StandardRegistry};

    /// `T-AF-STANDARD-REGISTRY-0001-R02-001`
    #[test]
    fn draft_registry_is_structurally_valid() {
        let registry = StandardRegistry::draft_1_0();
        assert_eq!(registry.status(), RuleStatus::Draft);
        assert_eq!(registry.rules().len(), 2);
        assert!(registry.validate().is_ok());
    }

    /// `T-AF-STANDARD-REGISTRY-0001-R02-002`
    #[test]
    fn draft_registry_exposes_stable_rule_metadata() {
        let registry = StandardRegistry::draft_1_0();
        let descriptor = registry.find("STD-ID-001");
        assert_eq!(
            descriptor.map(super::RuleDescriptor::title),
            Some("Stable serialized identity")
        );
    }
}
