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

/// `T-AF-FINDING-MODEL-0001-R01-004`
/// Fortress requirement: AF-FINDING-MODEL-0001-R01
#[test]
fn accepted_false_and_missing_premises_preserve_all_any_truth_tables() {
    use fortress_core::proof::ProofState::{Refuted as F, Satisfied as T, Unknown as U};
    use std::collections::BTreeMap;
    let table = [
        (T, T, T, T),
        (T, F, F, T),
        (T, U, U, T),
        (F, T, F, T),
        (F, F, F, F),
        (F, U, F, U),
        (U, T, U, T),
        (U, F, F, U),
        (U, U, U, U),
    ];
    for (left, right, all, any) in table {
        let states = BTreeMap::from([("evidence:a".into(), left), ("evidence:b".into(), right)]);
        for (operator, expected) in [(ProofOperator::All, all), (ProofOperator::Any, any)] {
            let graph = ProofGraph::new(
                "root",
                vec![
                    leaf("a", "evidence:a"),
                    leaf("b", "evidence:b"),
                    ProofExpression {
                        node_id: "root".into(),
                        operator,
                        required_refs: vec![],
                        children: vec!["a".into(), "b".into()],
                    },
                ],
            );
            assert_eq!(graph.evaluate(&references(), &states).unwrap(), expected);
            let accepted = states
                .iter()
                .filter(|(_, state)| **state == T)
                .map(|(id, _)| id.clone())
                .collect();
            assert_eq!(
                graph.is_satisfied(&references(), &accepted).unwrap(),
                expected == T
            );
        }
    }
    let graph = ProofGraph::new(
        "root",
        vec![ProofExpression {
            node_id: "root".into(),
            operator: ProofOperator::Leaf,
            required_refs: vec![EvidenceReference::new("evidence:a").unwrap()],
            children: vec![],
        }],
    );
    assert_eq!(graph.evaluate(&references(), &BTreeMap::new()).unwrap(), U);
    assert!(
        graph
            .evaluate(&references(), &BTreeMap::from([("foreign".into(), T)]))
            .is_err()
    );
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

/// `T-AF-FINDING-MODEL-0001-R01-003`
/// Fortress requirement: AF-FINDING-MODEL-0001-R01
#[test]
fn proof_alternative_with_missing_premise_is_not_sufficient() {
    let graph = ProofGraph::new(
        "root",
        vec![
            leaf("complete", "evidence:a"),
            ProofExpression {
                node_id: "incomplete".into(),
                operator: ProofOperator::All,
                required_refs: vec![EvidenceReference::new("evidence:b").unwrap()],
                children: vec!["complete".into()],
            },
            ProofExpression {
                node_id: "root".into(),
                operator: ProofOperator::Any,
                required_refs: Vec::new(),
                children: vec!["complete".into(), "incomplete".into()],
            },
        ],
    );
    let known = references();
    let only_a = BTreeSet::from(["evidence:a".to_owned()]);
    assert!(graph.is_satisfied(&known, &only_a).unwrap());
    let all = ProofGraph::new(
        "root",
        vec![
            leaf("complete", "evidence:a"),
            leaf("incomplete", "evidence:b"),
            ProofExpression {
                node_id: "root".into(),
                operator: ProofOperator::All,
                required_refs: Vec::new(),
                children: vec!["complete".into(), "incomplete".into()],
            },
        ],
    );
    assert!(!all.is_satisfied(&known, &only_a).unwrap());
    assert!(!graph.is_satisfied(&known, &BTreeSet::new()).unwrap());
}
