//! Evaluation-local indexing for deterministic behavioral-event path queries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::RealizationCoverage;

#[derive(Clone)]
pub(super) struct IndexedEventGraph<'a> {
    labels: Vec<&'a str>,
    indices: BTreeMap<&'a str, usize>,
    adjacency: Vec<Vec<(usize, RealizationCoverage)>>,
}

impl<'a> IndexedEventGraph<'a> {
    pub(super) fn try_new(
        events: impl ExactSizeIterator<Item = &'a str> + Clone,
        edges: impl ExactSizeIterator<Item = (&'a str, &'a str, RealizationCoverage)> + Clone,
        max_bytes: usize,
    ) -> Option<Self> {
        // Admit the complete endpoint union before allocating. Include index,
        // adjacency, allocator/collection overhead and one complete BFS scratch.
        // Saturated or excessive demand uses the unchanged legacy algorithm.
        let upper_nodes = events.len().checked_add(edges.len().checked_mul(2)?)?;
        let charge = upper_nodes
            .checked_mul(192)?
            .checked_add(edges.len().checked_mul(32)?)?
            .checked_add(4096)?;
        if charge > max_bytes {
            return None;
        }
        let mut indices = BTreeMap::new();
        for id in events.chain(
            edges
                .clone()
                .flat_map(|(source, target, _)| [source, target]),
        ) {
            indices.entry(id).or_insert(0);
        }
        let labels = indices.keys().copied().collect::<Vec<_>>();
        for (index, value) in indices.values_mut().enumerate() {
            *value = index;
        }
        let mut degrees = vec![0usize; labels.len()];
        for (source, _, _) in edges.clone() {
            let index = *indices.get(source)?;
            degrees[index] = degrees[index].checked_add(1)?;
        }
        let mut adjacency = degrees
            .into_iter()
            .map(Vec::with_capacity)
            .collect::<Vec<_>>();
        for (source, target, coverage) in edges {
            adjacency[*indices.get(source)?].push((*indices.get(target)?, coverage));
        }
        for targets in &mut adjacency {
            // Numeric IDs follow exact string order, including endpoint-only
            // nodes. This preserves first-visited coverage and tie-breaking.
            targets.sort_unstable();
            targets.dedup();
        }
        Some(Self {
            labels,
            indices,
            adjacency,
        })
    }

    pub(super) fn path(
        &self,
        sources: &[String],
        targets: &BTreeSet<String>,
        forbidden: &BTreeSet<String>,
        combine: impl Fn(RealizationCoverage, RealizationCoverage) -> RealizationCoverage,
    ) -> Option<(Vec<String>, RealizationCoverage)> {
        // The original BFS checks every initial source before any descendants.
        // This also preserves zero-hop paths for sources absent from the model.
        if let Some(source) = sources
            .iter()
            .find(|source| !forbidden.contains(*source) && targets.contains(*source))
        {
            return Some((vec![source.clone()], RealizationCoverage::Proven));
        }
        let mut target_flags = vec![false; self.labels.len()];
        let mut forbidden_flags = vec![false; self.labels.len()];
        for target in targets {
            if let Some(index) = self.indices.get(target.as_str()) {
                target_flags[*index] = true;
            }
        }
        for excluded in forbidden {
            if let Some(index) = self.indices.get(excluded.as_str()) {
                forbidden_flags[*index] = true;
            }
        }
        let mut previous = vec![usize::MAX; self.labels.len()];
        let mut coverage = vec![None; self.labels.len()];
        let mut queue = VecDeque::with_capacity(self.labels.len());
        for source in sources {
            if let Some(index) = self.indices.get(source.as_str()).copied()
                && !forbidden_flags[index]
                && coverage[index].is_none()
            {
                coverage[index] = Some(RealizationCoverage::Proven);
                queue.push_back(index);
            }
        }
        while let Some(current) = queue.pop_front() {
            if target_flags[current] {
                let mut path = vec![self.labels[current].to_owned()];
                let mut cursor = current;
                while previous[cursor] != usize::MAX {
                    cursor = previous[cursor];
                    path.push(self.labels[cursor].to_owned());
                }
                path.reverse();
                return Some((path, coverage[current].expect("queued node has coverage")));
            }
            for (next, edge_coverage) in &self.adjacency[current] {
                if forbidden_flags[*next] || coverage[*next].is_some() {
                    continue;
                }
                coverage[*next] = Some(combine(
                    coverage[current].expect("queued node has coverage"),
                    *edge_coverage,
                ));
                previous[*next] = current;
                queue.push_back(*next);
            }
        }
        None
    }
}
