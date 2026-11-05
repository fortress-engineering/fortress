//! Exact path and coverage controls against the original string-based BFS.

use super::{RealizationCoverage, event_graph::IndexedEventGraph};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn combine(left: RealizationCoverage, right: RealizationCoverage) -> RealizationCoverage {
    use RealizationCoverage::{Partial, Proven, Unknown, Unsupported};
    match (left, right) {
        (Unsupported, _) | (_, Unsupported) => Unsupported,
        (Unknown, _) | (_, Unknown) => Unknown,
        (Partial, _) | (_, Partial) => Partial,
        (Proven, Proven) => Proven,
    }
}

fn original(
    events: &[String],
    edges: &[(String, String, RealizationCoverage)],
    sources: &[String],
    targets: &BTreeSet<String>,
    forbidden: &BTreeSet<String>,
) -> Option<(Vec<String>, RealizationCoverage)> {
    let mut adjacency = BTreeMap::<String, Vec<(String, RealizationCoverage)>>::new();
    for event in events {
        adjacency.entry(event.clone()).or_default();
    }
    for (source, target, coverage) in edges {
        adjacency
            .entry(source.clone())
            .or_default()
            .push((target.clone(), *coverage));
    }
    for neighbors in adjacency.values_mut() {
        neighbors.sort();
        neighbors.dedup();
    }
    let mut queue = VecDeque::new();
    let mut previous = BTreeMap::<String, (String, RealizationCoverage)>::new();
    let mut coverage = BTreeMap::<String, RealizationCoverage>::new();
    for source in sources {
        if !forbidden.contains(source) {
            queue.push_back(source.clone());
            coverage.insert(source.clone(), RealizationCoverage::Proven);
        }
    }
    while let Some(current) = queue.pop_front() {
        if targets.contains(&current) {
            let mut path = vec![current.clone()];
            let mut cursor = current.clone();
            while let Some((parent, _)) = previous.get(&cursor) {
                path.push(parent.clone());
                cursor = parent.clone();
            }
            path.reverse();
            return Some((
                path,
                coverage
                    .get(&current)
                    .copied()
                    .unwrap_or(RealizationCoverage::Unknown),
            ));
        }
        for (next, edge_coverage) in adjacency.get(&current).into_iter().flatten() {
            if forbidden.contains(next) || coverage.contains_key(next) {
                continue;
            }
            let combined = combine(
                coverage
                    .get(&current)
                    .copied()
                    .unwrap_or(RealizationCoverage::Unknown),
                *edge_coverage,
            );
            coverage.insert(next.clone(), combined);
            previous.insert(next.clone(), (current.clone(), *edge_coverage));
            queue.push_back(next.clone());
        }
    }
    None
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-008`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn indexed_paths_preserve_the_original_order_coverage_and_endpoint_semantics() {
    let mut seed = 20_261_014_u64;
    let variants = [
        RealizationCoverage::Proven,
        RealizationCoverage::Partial,
        RealizationCoverage::Unknown,
        RealizationCoverage::Unsupported,
    ];
    for case in 0..1024usize {
        let count = case % 13;
        let labels = (0..count + 2)
            .map(|n| format!("node:{n:02}:é"))
            .collect::<Vec<_>>();
        let events = labels[..count].to_vec();
        let mut edges = Vec::new();
        for source in &labels {
            for target in &labels {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                if seed >> 61 == 0 {
                    edges.push((
                        source.clone(),
                        target.clone(),
                        variants
                            [usize::try_from((seed >> 8) % 4).expect("coverage index fits usize")],
                    ));
                }
            }
        }
        if let Some(edge) = edges.first().cloned() {
            edges.push(edge);
        }
        let indexed = IndexedEventGraph::try_new(
            events.iter().map(String::as_str),
            edges.iter().map(|(s, t, c)| (s.as_str(), t.as_str(), *c)),
            64 * 1024 * 1024,
        )
        .expect("bounded graph");
        for query in 0..32usize {
            let first = labels[(case + query) % labels.len()].clone();
            let sources = vec![
                first.clone(),
                "unknown".into(),
                labels[(case * 3 + query) % labels.len()].clone(),
                first,
            ];
            let targets = labels
                .iter()
                .enumerate()
                .filter(|(i, _)| (i + query) % 3 == 0)
                .map(|(_, id)| id.clone())
                .chain((query % 4 == 0).then(|| "unknown".into()))
                .collect::<BTreeSet<_>>();
            let forbidden = labels
                .iter()
                .enumerate()
                .filter(|(i, _)| (i + query) % 5 == 0)
                .map(|(_, id)| id.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                indexed.path(&sources, &targets, &forbidden, combine),
                original(&events, &edges, &sources, &targets, &forbidden),
                "case {case} query {query}"
            );
        }
    }
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-009`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn admission_refuses_before_allocation_and_empty_graph_preserves_unknown_zero_hop() {
    let events = ["a", "b"];
    let edges = [("a", "b", RealizationCoverage::Partial)];
    let charge = (events.len() + 2 * edges.len()) * 192 + edges.len() * 32 + 4096;
    assert!(
        IndexedEventGraph::try_new(events.into_iter(), edges.into_iter(), charge - 1).is_none()
    );
    assert!(IndexedEventGraph::try_new(events.into_iter(), edges.into_iter(), charge).is_some());
    assert!(IndexedEventGraph::try_new(events.into_iter(), edges.into_iter(), 0).is_none());
    let empty = IndexedEventGraph::try_new(std::iter::empty(), std::iter::empty(), 4096)
        .expect("empty graph");
    let targets = BTreeSet::from(["unknown".to_owned()]);
    assert_eq!(
        empty.path(&["unknown".into()], &targets, &BTreeSet::new(), combine),
        Some((vec!["unknown".into()], RealizationCoverage::Proven))
    );
    assert_eq!(
        empty.path(&["unknown".into()], &targets, &targets, combine),
        None
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-010`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn equal_length_paths_keep_first_visited_coverage_instead_of_preferring_proof() {
    use RealizationCoverage::{Proven, Unknown};
    let events = ["source", "a", "b", "target"];
    let edges = [
        ("source", "b", Proven),
        ("source", "a", Unknown),
        ("a", "target", Proven),
        ("b", "target", Proven),
    ];
    let graph = IndexedEventGraph::try_new(events.into_iter(), edges.into_iter(), 1024 * 1024)
        .expect("graph");
    assert_eq!(
        graph.path(
            &["source".into()],
            &BTreeSet::from(["target".into()]),
            &BTreeSet::new(),
            combine
        ),
        Some((vec!["source".into(), "a".into(), "target".into()], Unknown))
    );
}

/// `T-AF-BEHAVIORAL-REALIZATION-0001-R02-011`
/// Fortress requirement: AF-BEHAVIORAL-REALIZATION-0001-R02
#[test]
fn overflow_refuses_without_consuming_or_allocating_the_input() {
    #[derive(Clone)]
    struct Huge;
    impl Iterator for Huge {
        type Item = &'static str;
        fn next(&mut self) -> Option<Self::Item> {
            panic!("admission must precede iteration");
        }
        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, Some(usize::MAX))
        }
    }
    impl ExactSizeIterator for Huge {}
    assert!(IndexedEventGraph::try_new(Huge, std::iter::empty(), usize::MAX).is_none());
}
