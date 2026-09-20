//! Neutral proof references and structural support shape.
//!
//! A proof graph describes the premises a claim would need. Structural
//! validity does not assert that an evidence producer is trusted, that a
//! premise is true, or that the governed claim is favorable.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

/// First wire version of the shared proof graph.
pub const PROOF_GRAPH_VERSION: u16 = 1;

/// A stable citation to an evidence node, without a trust assertion.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EvidenceReference(String);

impl EvidenceReference {
    /// Creates a citation from a non-empty stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProofValidationError::InvalidReference`] for empty or
    /// whitespace/control-bearing identifiers.
    pub fn new(id: impl Into<String>) -> Result<Self, ProofValidationError> {
        let id = id.into();
        if !stable_identifier(&id) {
            return Err(ProofValidationError::InvalidReference(id));
        }
        Ok(Self(id))
    }

    /// Returns the cited stable identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.0
    }
}

/// Logical shape of one proof node; no operator makes premises true by itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofOperator {
    /// Direct evidence premises, with no child proof nodes.
    Leaf,
    /// Every named child and mandatory reference is necessary.
    All,
    /// At least one complete child alternative, plus mandatory references.
    Any,
}

/// One named node in an acyclic shared proof graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofExpression {
    /// Stable graph-local node identity.
    pub node_id: String,
    /// Direct premise or logical combination.
    pub operator: ProofOperator,
    /// Sorted, distinct evidence citations mandatory at this node.
    pub required_refs: Vec<EvidenceReference>,
    /// Sorted, distinct child node identities.
    pub children: Vec<String>,
}

/// Complete structural proof record with one explicit root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofGraph {
    /// Wire version of this graph shape.
    pub schema_version: u16,
    /// Node whose expression represents the obligation.
    pub root_node_id: String,
    /// Nodes in strictly increasing identity order.
    pub nodes: Vec<ProofExpression>,
}

impl ProofGraph {
    /// Creates a graph at the current wire version; validation remains explicit.
    #[must_use]
    pub fn new(root_node_id: impl Into<String>, nodes: Vec<ProofExpression>) -> Self {
        Self {
            schema_version: PROOF_GRAPH_VERSION,
            root_node_id: root_node_id.into(),
            nodes,
        }
    }

    /// Validates graph shape and resolves every evidence citation.
    ///
    /// The caller supplies exact known evidence identities. This method never
    /// judges whether their content satisfies a claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProofValidationError`] on unsupported shape, noncanonical
    /// sets, cycles, dangling nodes/evidence, or empty support.
    pub fn validate(&self, known_refs: &BTreeSet<String>) -> Result<(), ProofValidationError> {
        if self.schema_version != PROOF_GRAPH_VERSION {
            return Err(ProofValidationError::UnsupportedVersion(
                self.schema_version,
            ));
        }
        if !stable_identifier(&self.root_node_id) {
            return Err(ProofValidationError::InvalidNode(self.root_node_id.clone()));
        }
        let mut by_id = BTreeMap::new();
        let mut previous_node: Option<&str> = None;
        for node in &self.nodes {
            if !stable_identifier(&node.node_id) {
                return Err(ProofValidationError::InvalidNode(node.node_id.clone()));
            }
            if previous_node.is_some_and(|previous| previous >= node.node_id.as_str()) {
                return Err(ProofValidationError::NonCanonicalOrder("nodes".to_owned()));
            }
            previous_node = Some(&node.node_id);
            by_id.insert(node.node_id.as_str(), node);

            validate_node(node, known_refs)?;
        }
        if !by_id.contains_key(self.root_node_id.as_str()) {
            return Err(ProofValidationError::DanglingNode(
                self.root_node_id.clone(),
            ));
        }
        for node in &self.nodes {
            for child in &node.children {
                if !by_id.contains_key(child.as_str()) {
                    return Err(ProofValidationError::DanglingNode(child.clone()));
                }
            }
        }

        validate_reachability(&by_id, &self.root_node_id)?;
        validate_acyclic(&self.nodes, &self.root_node_id)
    }
}

fn validate_node(
    node: &ProofExpression,
    known_refs: &BTreeSet<String>,
) -> Result<(), ProofValidationError> {
    let mut previous_ref: Option<&EvidenceReference> = None;
    for reference in &node.required_refs {
        if !stable_identifier(reference.id()) {
            return Err(ProofValidationError::InvalidReference(
                reference.id().to_owned(),
            ));
        }
        if previous_ref == Some(reference) {
            return Err(ProofValidationError::DuplicateMandatoryRef(
                reference.id().to_owned(),
            ));
        }
        if previous_ref.is_some_and(|previous| previous > reference) {
            return Err(ProofValidationError::NonCanonicalOrder(
                node.node_id.clone(),
            ));
        }
        if !known_refs.contains(reference.id()) {
            return Err(ProofValidationError::DanglingEvidence(
                reference.id().to_owned(),
            ));
        }
        previous_ref = Some(reference);
    }
    if !strictly_increasing(&node.children) {
        return Err(ProofValidationError::NonCanonicalOrder(
            node.node_id.clone(),
        ));
    }
    if node.operator == ProofOperator::Leaf && !node.children.is_empty() {
        return Err(ProofValidationError::LeafHasChildren(node.node_id.clone()));
    }
    let unsupported = match node.operator {
        ProofOperator::Leaf => node.required_refs.is_empty(),
        ProofOperator::All => node.required_refs.is_empty() && node.children.is_empty(),
        ProofOperator::Any => node.children.is_empty(),
    };
    if unsupported {
        return Err(ProofValidationError::EmptySupport(node.node_id.clone()));
    }
    Ok(())
}

fn validate_reachability(
    by_id: &BTreeMap<&str, &ProofExpression>,
    root: &str,
) -> Result<(), ProofValidationError> {
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::from([root]);
    while let Some(id) = queue.pop_front() {
        if reachable.insert(id) {
            let node = by_id
                .get(id)
                .ok_or_else(|| ProofValidationError::DanglingNode(id.to_owned()))?;
            queue.extend(node.children.iter().map(String::as_str));
        }
    }
    if reachable.len() != by_id.len() {
        let orphan = by_id
            .keys()
            .find(|id| !reachable.contains(**id))
            .copied()
            .unwrap_or(root);
        return Err(ProofValidationError::UnreachableNode(orphan.to_owned()));
    }
    Ok(())
}

fn validate_acyclic(nodes: &[ProofExpression], root: &str) -> Result<(), ProofValidationError> {
    let mut remaining_children: BTreeMap<&str, usize> = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.children.len()))
        .collect();
    let mut parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        for child in &node.children {
            parents.entry(child).or_default().push(&node.node_id);
        }
    }
    let mut ready: VecDeque<&str> = remaining_children
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0;
    while let Some(id) = ready.pop_front() {
        visited += 1;
        if let Some(referrers) = parents.get(id) {
            for parent in referrers {
                let count = remaining_children
                    .get_mut(parent)
                    .ok_or_else(|| ProofValidationError::DanglingNode((*parent).to_owned()))?;
                *count -= 1;
                if *count == 0 {
                    ready.push_back(parent);
                }
            }
        }
    }
    if visited != nodes.len() {
        let cycle = remaining_children
            .iter()
            .find(|(_, count)| **count > 0)
            .map_or(root, |(id, _)| *id);
        return Err(ProofValidationError::Cycle(cycle.to_owned()));
    }
    Ok(())
}

fn stable_identifier(id: &str) -> bool {
    !id.is_empty() && id.trim() == id && !id.chars().any(char::is_control)
}

fn strictly_increasing(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// A structural error; it does not encode a semantic claim verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofValidationError {
    /// The graph has an unrecognized wire version.
    UnsupportedVersion(u16),
    /// A node identifier is empty or unstable.
    InvalidNode(String),
    /// An evidence identifier is empty or unstable.
    InvalidReference(String),
    /// A set-valued field is out of order or contains duplicate children.
    NonCanonicalOrder(String),
    /// One mandatory reference appears more than once at a node.
    DuplicateMandatoryRef(String),
    /// The named child/root node does not exist.
    DanglingNode(String),
    /// A cited evidence identity was not supplied by the caller.
    DanglingEvidence(String),
    /// A leaf listed child proof nodes.
    LeafHasChildren(String),
    /// A node could establish favorability without any premise.
    EmptySupport(String),
    /// A node is not reachable from the declared root.
    UnreachableNode(String),
    /// The graph contains a dependency cycle.
    Cycle(String),
}

impl Display for ProofValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid proof graph: {self:?}")
    }
}

impl Error for ProofValidationError {}
