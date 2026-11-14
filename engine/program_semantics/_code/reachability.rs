//! Bounded integer scratch for the existing directed call-reachability relation.
use std::collections::{BTreeMap, BTreeSet};

pub(super) const REACHABILITY_SCRATCH_BYTES: usize = 16 * 1024 * 1024;

/// All scratch keys borrow the current complete component. Refusal leaves the
/// original producer responsible for the entire relation; no partial map escapes.
pub(super) fn indexed_reachability(
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    maximum: usize,
) -> Option<BTreeMap<String, Vec<String>>> {
    let edge_count = adjacency
        .values()
        .try_fold(0_usize, |sum, targets| sum.checked_add(targets.len()))?;
    // Complete component keys are required. Unknown targets fall back to the
    // original traversal rather than being silently dropped or reinterpreted.
    if adjacency
        .len()
        .checked_mul(512)?
        .checked_add(edge_count.checked_mul(16)?)?
        > maximum
        || adjacency
            .values()
            .flatten()
            .any(|target| !adjacency.contains_key(target))
    {
        return None;
    }
    let names = adjacency.keys().map(String::as_str).collect::<Vec<_>>();
    let index = names
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, i))
        .collect::<BTreeMap<_, _>>();
    let edges = names
        .iter()
        .map(|name| {
            adjacency
                .get(*name)
                .into_iter()
                .flatten()
                .map(|target| index[target.as_str()])
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut visited = vec![false; names.len()];
    let mut pending = Vec::with_capacity(names.len());
    let mut reached = Vec::with_capacity(names.len());
    let mut result = BTreeMap::new();
    for origin in adjacency.keys() {
        for &next in &edges[index[origin.as_str()]] {
            if !visited[next] {
                visited[next] = true;
                pending.push(next);
                reached.push(next);
            }
        }
        while let Some(next) = pending.pop() {
            for &target in &edges[next] {
                if !visited[target] {
                    visited[target] = true;
                    pending.push(target);
                    reached.push(target);
                }
            }
        }
        reached.sort_unstable();
        result.insert(
            origin.clone(),
            reached.iter().map(|&i| names[i].to_owned()).collect(),
        );
        for i in reached.drain(..) {
            visited[i] = false;
        }
    }
    Some(result)
}
