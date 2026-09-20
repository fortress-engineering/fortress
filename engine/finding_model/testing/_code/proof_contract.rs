//! Black-box vectors for the neutral proof graph.

use fortress_core::proof::{
    EvidenceReference, ProofExpression, ProofGraph, ProofOperator, ProofValidationError,
};
use std::collections::BTreeSet;

fn references() -> BTreeSet<String> {
    ["evidence:a", "evidence:b"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn leaf(id: &str, reference: &str) -> ProofExpression {
    ProofExpression {
        node_id: id.to_owned(),
        operator: ProofOperator::Leaf,
        required_refs: vec![EvidenceReference::new(reference).expect("reference")],
        children: Vec::new(),
    }
}

/// `T-AF-FINDING-MODEL-0001-R01-001`
/// Fortress requirement: AF-FINDING-MODEL-0001-R01
#[test]
fn proof_cycles_dangling_and_empty_support_fail() {
    let refs = references();
    let valid = ProofGraph::new(
        "root",
        vec![
            leaf("a", "evidence:a"),
            leaf("b", "evidence:b"),
            ProofExpression {
                node_id: "root".to_owned(),
                operator: ProofOperator::All,
                required_refs: Vec::new(),
                children: vec!["a".to_owned(), "b".to_owned()],
            },
        ],
    );
    assert!(valid.validate(&refs).is_ok());

    let direct_all = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::All,
            required_refs: vec![EvidenceReference::new("evidence:a").expect("reference")],
            children: Vec::new(),
        }],
    );
    assert!(direct_all.validate(&refs).is_ok());

    let dangling = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::Any,
            required_refs: Vec::new(),
            children: vec!["missing".to_owned()],
        }],
    );
    assert!(matches!(
        dangling.validate(&refs),
        Err(ProofValidationError::DanglingNode(_))
    ));

    let empty = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::All,
            required_refs: Vec::new(),
            children: Vec::new(),
        }],
    );
    assert!(matches!(
        empty.validate(&refs),
        Err(ProofValidationError::EmptySupport(_))
    ));

    let cycle = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::Any,
            required_refs: Vec::new(),
            children: vec!["root".to_owned()],
        }],
    );
    assert!(matches!(
        cycle.validate(&refs),
        Err(ProofValidationError::Cycle(_))
    ));
}

/// `T-AF-FINDING-MODEL-0001-R01-002`
/// Fortress requirement: AF-FINDING-MODEL-0001-R01
#[test]
fn proof_references_are_canonical_and_resolved() {
    let refs = references();
    let unknown = ProofGraph::new("root", vec![leaf("root", "evidence:unknown")]);
    assert!(matches!(
        unknown.validate(&refs),
        Err(ProofValidationError::DanglingEvidence(_))
    ));

    let duplicate = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::Leaf,
            required_refs: vec![
                EvidenceReference::new("evidence:a").expect("reference"),
                EvidenceReference::new("evidence:a").expect("reference"),
            ],
            children: Vec::new(),
        }],
    );
    assert!(matches!(
        duplicate.validate(&refs),
        Err(ProofValidationError::DuplicateMandatoryRef(_))
    ));

    let unordered = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".to_owned(),
            operator: ProofOperator::Leaf,
            required_refs: vec![
                EvidenceReference::new("evidence:b").expect("reference"),
                EvidenceReference::new("evidence:a").expect("reference"),
            ],
            children: Vec::new(),
        }],
    );
    assert!(matches!(
        unordered.validate(&refs),
        Err(ProofValidationError::NonCanonicalOrder(_))
    ));
}
