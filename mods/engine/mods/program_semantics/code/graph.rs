//! Deterministic graph derivations over resolved static PSM calls.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    CallComponent, CallResolutionState, CallTopology, CrossModuleCall, ExecutableSymbol,
    ProgramCall, canonical_fact_id, symbol_index,
};

pub(super) fn derive_call_topology(
    symbols: &[ExecutableSymbol],
    calls: &[ProgramCall],
) -> CallTopology {
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
    let transitive_reachability = ids
        .iter()
        .map(|id| (id.clone(), reachable_from(id, &adjacency)))
        .collect();
    let mut components = strongly_connected_components(&ids, &adjacency);
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
    CallTopology {
        direct_callees: to_vectors(outgoing_calls),
        direct_callers: to_vectors(incoming_calls),
        transitive_reachability,
        strongly_connected_components: components,
        recursive_symbols,
        entry_candidates,
        leaf_symbols,
        cross_package_calls,
    }
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
) -> Vec<CallComponent> {
    let mut state = TarjanState::default();
    for symbol in symbols {
        if !state.indices.contains_key(symbol) {
            strong_connect(symbol, adjacency, &mut state);
        }
    }
    state
        .components
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
