//! Derived architecture dependency and ownership views.
//!
//! Module Contract v2 owns functional intent and the CCG owns its canonical
//! derived dependency graph. This module projects those CCG edges and derives
//! physical territory from canonical Module containment. It introduces no
//! writable architecture manifest authority.

pub(crate) const DEPENDENCY_RULE_SOURCE: &str = include_str!("../data/dependency_rule.json");

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::contract_coherency::ContractCoherencyGraph;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of the declared dependency-cycle rule.
pub const ARCH_DEPENDENCY_RULE_ID: &str = "ARCH-DEPENDENCY-001";

const ARCH_DEPENDENCY_REMEDIATION: &str = "Separate responsibilities to restore one-way dependency flow or model a genuinely inseparable strongly connected cluster as one Module. A temporary exception requires a governed transition or exemption.";

/// Deterministic architecture view derived from contracts and containment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureManifest {
    components: Vec<ComponentDeclaration>,
    dependency_cycles: Vec<Vec<String>>,
}

impl ArchitectureManifest {
    /// Projects dependency edges and exact observed ownership from the canonical CCG.
    #[must_use]
    pub fn from_ccg(contracts: &ContractCoherencyGraph, observed_paths: &[String]) -> Self {
        let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
        for requirement in contracts.direct_requirements() {
            dependencies
                .entry(requirement.consumer().to_owned())
                .or_default()
                .insert(requirement.provider().to_owned());
        }
        let mut owned = BTreeMap::<String, Vec<String>>::new();
        for path in observed_paths {
            if let Some(owner) = deepest_owner(contracts, path) {
                owned.entry(owner).or_default().push(path.clone());
            }
        }
        let mut components: Vec<ComponentDeclaration> = contracts
            .modules()
            .iter()
            .map(|(id, module)| ComponentDeclaration {
                id: id.clone(),
                title: module.contract().display_name().to_owned(),
                paths: owned.remove(id).unwrap_or_default(),
                depends_on: dependencies
                    .remove(id)
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            })
            .collect();
        components.sort_by(|left, right| left.id.cmp(&right.id));
        Self {
            components,
            dependency_cycles: contracts.dependency_cycles(),
        }
    }

    /// Constructs a deterministic architecture view for specification fixtures.
    ///
    /// This constructor creates evaluation input only; it is not a serialized
    /// repository authority.
    #[must_use]
    pub fn from_components(mut components: Vec<ComponentDeclaration>) -> Self {
        components.sort_by(|left, right| left.id.cmp(&right.id));
        let dependency_cycles = first_dependency_cycle(&components).into_iter().collect();
        Self {
            components,
            dependency_cycles,
        }
    }

    /// Returns derived architecture components.
    #[must_use]
    pub fn components(&self) -> &[ComponentDeclaration] {
        &self.components
    }

    /// Returns dependency cycles compiled by the CCG or by fixture construction.
    #[must_use]
    pub fn dependency_cycles(&self) -> &[Vec<String>] {
        &self.dependency_cycles
    }

    /// Evaluates draft rule `ARCH-DEPENDENCY-001` against derived edges.
    ///
    /// Returns the first deterministic directed cycle, if one exists. A `None`
    /// result describes only the resolved contract graph and is not a
    /// certification claim.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError`] if normalized finding construction fails.
    pub fn evaluate_acyclic_dependencies(
        &self,
        standard_edition: &str,
    ) -> Result<Option<CanonicalFinding>, FindingError> {
        let Some(entities) = self.dependency_cycles.first() else {
            return Ok(None);
        };
        let route = entities.join(" -> ");
        let definition = RuleFindingDefinition::new(
            ARCH_DEPENDENCY_RULE_ID,
            1,
            FindingCategory::Architecture,
            ARCH_DEPENDENCY_REMEDIATION,
        )?;
        let occurrence = FindingOccurrence::new(
            entities.clone(),
            FindingLocation::none(),
            format!("CCG Module capability dependency graph contains a cycle: {route}."),
        )?;
        let evaluator =
            EvaluatorProvenance::new("fortress-core/architecture", env!("CARGO_PKG_VERSION"))?;
        CanonicalFinding::failure(definition, occurrence, evaluator, standard_edition, None)
            .map(Some)
    }
}

fn first_dependency_cycle(components: &[ComponentDeclaration]) -> Option<Vec<String>> {
    let adjacency: BTreeMap<&str, Vec<&str>> = components
        .iter()
        .map(|component| {
            (
                component.id.as_str(),
                component.depends_on.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let mut states = HashMap::with_capacity(components.len());
    for start in adjacency.keys().copied() {
        if states.contains_key(start) {
            continue;
        }
        states.insert(start, VisitState::Visiting);
        let mut path = vec![start];
        let mut stack = vec![(start, 0_usize)];
        while let Some(&(node, next_offset)) = stack.last() {
            let dependencies = adjacency.get(node).map_or(&[][..], Vec::as_slice);
            let Some(&dependency) = dependencies.get(next_offset) else {
                states.insert(node, VisitState::Complete);
                stack.pop();
                path.pop();
                continue;
            };
            if let Some(last) = stack.last_mut() {
                last.1 += 1;
            }
            match states
                .get(dependency)
                .copied()
                .unwrap_or(VisitState::Unseen)
            {
                VisitState::Unseen => {
                    states.insert(dependency, VisitState::Visiting);
                    path.push(dependency);
                    stack.push((dependency, 0));
                }
                VisitState::Visiting => {
                    if let Some(cycle_start) =
                        path.iter().position(|identity| *identity == dependency)
                    {
                        let mut entities: Vec<String> = path
                            .iter()
                            .skip(cycle_start)
                            .map(|identity| (*identity).to_owned())
                            .collect();
                        entities.push(dependency.to_owned());
                        return Some(entities);
                    }
                }
                VisitState::Complete => {}
            }
        }
    }
    None
}

/// One derived Module node with exact direct territory and capability edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentDeclaration {
    id: String,
    title: String,
    paths: Vec<String>,
    depends_on: Vec<String>,
}

impl ComponentDeclaration {
    /// Creates a deterministic component for specification fixtures.
    #[must_use]
    pub fn new<I, P, J, D>(
        id: impl Into<String>,
        title: impl Into<String>,
        paths: I,
        dependencies: J,
    ) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
        J: IntoIterator<Item = D>,
        D: Into<String>,
    {
        let mut paths: Vec<String> = paths.into_iter().map(Into::into).collect();
        paths.sort();
        let mut depends_on: Vec<String> = dependencies.into_iter().map(Into::into).collect();
        depends_on.sort();
        Self {
            id: id.into(),
            title: title.into(),
            paths,
            depends_on,
        }
    }

    /// Returns the stable Module identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the Module display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns exact observed paths owned by the Module.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Returns provider Module identities derived from capability requirements.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.depends_on
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitState {
    Unseen,
    Visiting,
    Complete,
}

fn deepest_owner(contracts: &ContractCoherencyGraph, path: &str) -> Option<String> {
    contracts
        .modules()
        .iter()
        .filter(|(_, module)| {
            module.path().is_empty()
                || path == module.path()
                || path.starts_with(&format!("{}/", module.path()))
        })
        .max_by_key(|(_, module)| module.path().len())
        .map(|(id, _)| id.clone())
}
