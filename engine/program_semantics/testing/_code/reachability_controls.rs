//! Independent original-traversal controls for bounded call-graph indexing.
use super::reachability::{REACHABILITY_SCRATCH_BYTES, indexed_reachability};
use std::collections::{BTreeMap, BTreeSet};

fn original(graph: &BTreeMap<String, BTreeSet<String>>) -> BTreeMap<String, Vec<String>> {
    graph
        .keys()
        .map(|origin| {
            let mut visited = BTreeSet::new();
            let mut pending = graph.get(origin).cloned().unwrap_or_default();
            while let Some(next) = pending.pop_first() {
                if visited.insert(next.clone()) {
                    pending.extend(graph.get(&next).into_iter().flatten().cloned());
                }
            }
            (origin.clone(), visited.into_iter().collect())
        })
        .collect()
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R10-001`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R10
#[test]
fn indexed_graphs_preserve_the_independent_original_relation() {
    let mut seed = 0x25a9_b71c_u64;
    for case in 0..1024 {
        let size = 1 + case % 32;
        let mut graph = (0..size)
            .map(|i| (format!("symbol_{i:03}"), BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        for i in 0..size {
            for j in 0..size {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                if seed >> 60 < 3 {
                    graph
                        .get_mut(&format!("symbol_{i:03}"))
                        .unwrap()
                        .insert(format!("symbol_{j:03}"));
                }
            }
        }
        assert_eq!(
            indexed_reachability(&graph, REACHABILITY_SCRATCH_BYTES).unwrap(),
            original(&graph),
            "case {case}"
        );
    }
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R10-002`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R10
#[test]
fn scratch_refusal_never_returns_a_partial_relation() {
    let graph = BTreeMap::from([
        ("a".into(), BTreeSet::from(["b".into()])),
        ("b".into(), BTreeSet::new()),
    ]);
    assert!(indexed_reachability(&graph, 0).is_none());
    assert!(indexed_reachability(&graph, 1024).is_none());
    assert_eq!(
        indexed_reachability(&graph, 1040).unwrap(),
        original(&graph)
    );
    let incomplete = BTreeMap::from([("a".into(), BTreeSet::from(["missing".into()]))]);
    assert!(indexed_reachability(&incomplete, usize::MAX).is_none());
    assert_eq!(original(&incomplete)["a"], vec!["missing"]);
}

/// `T-AF-PROGRAM-SEMANTICS-0001-R10-003`
/// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R10
#[test]
fn source_edge_changes_and_direction_do_not_reuse_an_old_index() {
    let mut graph = BTreeMap::from([
        ("a".into(), BTreeSet::from(["b".into()])),
        ("b".into(), BTreeSet::new()),
        ("c".into(), BTreeSet::new()),
    ]);
    let before = indexed_reachability(&graph, REACHABILITY_SCRATCH_BYTES).unwrap();
    assert_eq!(before["a"], vec!["b"]);
    assert!(before["b"].is_empty());
    graph.get_mut("b").unwrap().insert("c".into());
    let after = indexed_reachability(&graph, REACHABILITY_SCRATCH_BYTES).unwrap();
    assert_eq!(after["a"], vec!["b", "c"]);
    assert_eq!(after, original(&graph));
    graph.get_mut("c").unwrap().insert("a".into());
    assert_eq!(
        indexed_reachability(&graph, REACHABILITY_SCRATCH_BYTES).unwrap(),
        original(&graph)
    );
    assert_eq!(before["a"], vec!["b"]);
}
