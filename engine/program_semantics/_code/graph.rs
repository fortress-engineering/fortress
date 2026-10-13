//! Deterministic graph derivations over resolved static PSM calls.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::{
    CallComponent, CallResolutionState, CallTopology, CrossModuleCall, ExecutableSymbol,
    ProgramCall, canonical_fact_id, symbol_index,
};

#[derive(Clone)]
pub(super) struct PreparedCallTopology {
    units: BTreeMap<Vec<String>, Rc<PreparedGraphUnit>>,
}

#[derive(Clone)]
struct PreparedGraphUnit {
    adjacency: BTreeMap<String, BTreeSet<String>>,
    symbol_metadata: BTreeMap<String, (String, bool)>,
    reachability: BTreeMap<String, Vec<String>>,
    components: BTreeMap<String, Vec<CallComponent>>,
}

impl PreparedCallTopology {
    pub(super) fn retained_components(&self) -> usize {
        self.units.len()
    }

    /// Operational cache charge, including graph keys and duplicate edges.
    /// This estimates retained allocations; process RSS is measured separately.
    pub(super) fn accounted_resident_bytes(&self) -> usize {
        self.units.iter().fold(0usize, |charge, (members, unit)| {
            let strings = members
                .iter()
                .chain(unit.adjacency.keys())
                .chain(unit.adjacency.values().flatten())
                .chain(unit.symbol_metadata.keys())
                .chain(unit.symbol_metadata.values().map(|(package, _)| package))
                .chain(unit.reachability.keys())
                .chain(unit.reachability.values().flatten())
                .chain(
                    unit.components
                        .values()
                        .flatten()
                        .flat_map(|component| component.symbols.iter()),
                );
            strings.fold(charge.saturating_add(1024), |sum, value| {
                sum.saturating_add(value.capacity().saturating_add(256))
            })
        })
    }
}

pub(super) struct PreparedCallTopologyResult {
    pub(super) topology: CallTopology,
    pub(super) preparation: PreparedCallTopology,
    pub(super) recomputed_components: usize,
    pub(super) reused_components: usize,
}

#[allow(clippy::too_many_lines)]
pub(super) fn prepare_call_topology(
    symbols: &[ExecutableSymbol],
    calls: &[ProgramCall],
    previous: Option<&PreparedCallTopology>,
) -> PreparedCallTopologyResult {
    let ids: BTreeSet<String> = symbols.iter().map(|symbol| symbol.id.clone()).collect();
    let mut outgoing_calls = ids
        .iter()
        .map(|id| (id.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut incoming_calls = outgoing_calls.clone();
    let index = symbol_index(symbols);
    let mut cross_package_calls = Vec::new();
    for call in calls
        .iter()
        .filter(|call| call.state == CallResolutionState::ResolvedStatic)
    {
        let Some(callee) = &call.callee else {
            continue;
        };
        outgoing_calls
            .entry(call.caller.clone())
            .or_default()
            .insert(callee.clone());
        incoming_calls
            .entry(callee.clone())
            .or_default()
            .insert(call.caller.clone());
        if index
            .get(call.caller.as_str())
            .zip(index.get(callee.as_str()))
            .is_some_and(|(caller, target)| caller.package != target.package)
        {
            cross_package_calls.push(call.id.clone());
        }
    }
    let adjacency = outgoing_calls.clone();
    let mut transitive_reachability = BTreeMap::new();
    let mut component_groups = BTreeMap::new();
    let mut units = BTreeMap::new();
    let mut recomputed_components = 0;
    let mut reused_components = 0;
    for members in weak_components(&ids, &adjacency, &incoming_calls) {
        let edges = members
            .iter()
            .map(|id| (id.clone(), adjacency.get(id).cloned().unwrap_or_default()))
            .collect::<BTreeMap<_, _>>();
        let symbol_metadata = members
            .iter()
            .filter_map(|id| {
                index
                    .get(id.as_str())
                    .map(|symbol| (id.clone(), (symbol.package.clone(), symbol.has_body())))
            })
            .collect::<BTreeMap<_, _>>();
        let key = members.iter().cloned().collect::<Vec<_>>();
        let retained = previous
            .and_then(|prepared| prepared.units.get(&key))
            .filter(|unit| unit.adjacency == edges && unit.symbol_metadata == symbol_metadata);
        let unit = if let Some(unit) = retained {
            reused_components += 1;
            Rc::clone(unit)
        } else {
            recomputed_components += 1;
            Rc::new(PreparedGraphUnit {
                reachability: members
                    .iter()
                    .map(|id| (id.clone(), reachable_from(id, &edges)))
                    .collect(),
                components: strongly_connected_components(&members, &edges),
                adjacency: edges,
                symbol_metadata,
            })
        };
        transitive_reachability.extend(unit.reachability.clone());
        component_groups.extend(
            unit.components
                .iter()
                .map(|(root, components)| (root.clone(), components.clone())),
        );
        units.insert(key, unit);
    }
    // Tarjan may start several directed searches inside one weak component.
    // Reassemble those searches by their original global root order before
    // deriving the historically ordered recursive-symbol vector.
    let mut components = component_groups.into_values().flatten().collect::<Vec<_>>();
    let recursive_symbols = components
        .iter()
        .filter(|component| component.recursive)
        .flat_map(|component| component.symbols.iter().cloned())
        .collect();
    components.sort();
    cross_package_calls.sort();
    cross_package_calls.dedup();
    let entry_candidates = symbols
        .iter()
        .filter(|symbol| {
            symbol.has_body()
                && incoming_calls
                    .get(&symbol.id)
                    .is_none_or(BTreeSet::is_empty)
        })
        .map(|symbol| symbol.id.clone())
        .collect();
    let leaf_symbols = symbols
        .iter()
        .filter(|symbol| {
            symbol.has_body()
                && outgoing_calls
                    .get(&symbol.id)
                    .is_none_or(BTreeSet::is_empty)
        })
        .map(|symbol| symbol.id.clone())
        .collect();
    let topology = CallTopology {
        direct_callees: to_vectors(outgoing_calls),
        direct_callers: to_vectors(incoming_calls),
        transitive_reachability,
        strongly_connected_components: components,
        recursive_symbols,
        entry_candidates,
        leaf_symbols,
        cross_package_calls,
    };
    PreparedCallTopologyResult {
        topology,
        preparation: PreparedCallTopology { units },
        recomputed_components,
        reused_components,
    }
}

fn weak_components(
    symbols: &BTreeSet<String>,
    outgoing: &BTreeMap<String, BTreeSet<String>>,
    incoming: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<BTreeSet<String>> {
    let mut remaining = symbols.clone();
    let mut result = Vec::new();
    while let Some(origin) = remaining.pop_first() {
        let mut members = BTreeSet::new();
        let mut pending = BTreeSet::from([origin]);
        while let Some(next) = pending.pop_first() {
            if members.insert(next.clone()) {
                remaining.remove(&next);
                pending.extend(outgoing.get(&next).into_iter().flatten().cloned());
                pending.extend(incoming.get(&next).into_iter().flatten().cloned());
            }
        }
        result.push(members);
    }
    result
}

pub(super) fn derive_module_boundaries(
    symbols: &[ExecutableSymbol],
    calls: &[ProgramCall],
) -> Vec<CrossModuleCall> {
    let index = symbol_index(symbols);
    let mut boundaries = Vec::new();
    for call in calls
        .iter()
        .filter(|call| call.state == CallResolutionState::ResolvedStatic)
    {
        let Some(callee_id) = &call.callee else {
            continue;
        };
        let Some((source_symbol, target_symbol)) = index
            .get(call.caller.as_str())
            .zip(index.get(callee_id.as_str()))
        else {
            continue;
        };
        let target_module = call
            .boundary_target_module
            .as_deref()
            .unwrap_or(&target_symbol.fortress_module);
        if source_symbol.fortress_module != target_module {
            boundaries.push(CrossModuleCall {
                caller: source_symbol.id.clone(),
                callee: target_symbol.id.clone(),
                source_module: source_symbol.fortress_module.clone(),
                target_module: target_module.into(),
                callee_module: target_symbol.fortress_module.clone(),
                call: call.id.clone(),
                evidence: call.evidence.clone(),
            });
        }
    }
    boundaries.sort();
    boundaries.dedup();
    boundaries
}

fn to_vectors(values: BTreeMap<String, BTreeSet<String>>) -> BTreeMap<String, Vec<String>> {
    values
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
}

fn reachable_from(origin: &str, adjacency: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut visited = BTreeSet::new();
    let mut pending = adjacency.get(origin).cloned().unwrap_or_default();
    while let Some(next) = pending.pop_first() {
        if visited.insert(next.clone()) {
            pending.extend(adjacency.get(&next).into_iter().flatten().cloned());
        }
    }
    visited.into_iter().collect()
}

fn strongly_connected_components(
    symbols: &BTreeSet<String>,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<String, Vec<CallComponent>> {
    let mut state = TarjanState::default();
    let mut groups = BTreeMap::new();
    for symbol in symbols {
        if !state.indices.contains_key(symbol) {
            let start = state.components.len();
            strong_connect(symbol, adjacency, &mut state);
            groups.insert(symbol.clone(), state.components[start..].to_vec());
        }
    }
    groups
        .into_iter()
        .map(|(root, components)| {
            (
                root,
                components
                    .into_iter()
                    .map(|symbols| {
                        let recursive = symbols.len() > 1
                            || symbols.first().is_some_and(|symbol| {
                                adjacency
                                    .get(symbol)
                                    .is_some_and(|targets| targets.contains(symbol))
                            });
                        CallComponent {
                            id: canonical_fact_id("call_scc", &symbols),
                            symbols,
                            recursive,
                        }
                    })
                    .collect(),
            )
        })
        .collect()
}

#[derive(Default)]
struct TarjanState {
    next_index: usize,
    stack: Vec<String>,
    on_stack: BTreeSet<String>,
    indices: BTreeMap<String, usize>,
    lowlinks: BTreeMap<String, usize>,
    components: Vec<Vec<String>>,
}

fn strong_connect(
    symbol: &str,
    adjacency: &BTreeMap<String, BTreeSet<String>>,
    state: &mut TarjanState,
) {
    let index = state.next_index;
    state.next_index += 1;
    state.indices.insert(symbol.into(), index);
    state.lowlinks.insert(symbol.into(), index);
    state.stack.push(symbol.into());
    state.on_stack.insert(symbol.into());
    for target in adjacency.get(symbol).into_iter().flatten() {
        if !state.indices.contains_key(target) {
            strong_connect(target, adjacency, state);
            let candidate = state.lowlinks[target];
            state
                .lowlinks
                .entry(symbol.into())
                .and_modify(|lowlink| *lowlink = (*lowlink).min(candidate));
        } else if state.on_stack.contains(target) {
            let candidate = state.indices[target];
            state
                .lowlinks
                .entry(symbol.into())
                .and_modify(|lowlink| *lowlink = (*lowlink).min(candidate));
        }
    }
    if state.lowlinks[symbol] == state.indices[symbol] {
        let mut component = Vec::new();
        while let Some(value) = state.stack.pop() {
            state.on_stack.remove(&value);
            component.push(value.clone());
            if value == symbol {
                break;
            }
        }
        component.sort();
        state.components.push(component);
    }
}
