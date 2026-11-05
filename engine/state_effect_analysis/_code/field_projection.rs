//! Bounded, evaluation-local aggregation of borrowed PSM field membership.

use std::collections::{BTreeMap, BTreeSet};

use crate::program_semantics::{ExecutableSymbol, ProgramSemanticModel};

// Optional scratch is bounded before any index allocation. Existing model and
// preparation charges are unchanged; refusal uses the original complete scan.
pub(super) const FIELD_PROJECTION_SCRATCH_BYTES: usize = 16 * 1024 * 1024;
pub(super) type FieldProjection<'a> = BTreeMap<&'a str, [BTreeSet<&'a str>; 2]>;

pub(super) fn field_projection_index<'a>(
    psm: &'a ProgramSemanticModel,
    symbols: &BTreeMap<&str, &ExecutableSymbol>,
    max_bytes: usize,
) -> Option<FieldProjection<'a>> {
    // Conservative independent reserves for each possible set entry and each
    // symbol bucket include standard-container headers, spare node capacity,
    // and alignment. All field strings and symbol keys are borrowed.
    let records = psm.state_reads().len().checked_add(psm.mutations().len())?;
    let charge = records
        .checked_mul(512)?
        .checked_add(symbols.len().checked_mul(2048)?)?
        .checked_add(std::mem::size_of::<FieldProjection<'_>>())?;
    if charge > max_bytes
        || psm
            .state_reads()
            .iter()
            .any(|read| !symbols.contains_key(read.symbol()))
        || psm
            .mutations()
            .iter()
            .any(|mutation| !symbols.contains_key(mutation.symbol()))
    {
        return None;
    }
    let mut fields = FieldProjection::new();
    for read in psm.state_reads() {
        if let Some(field) = read.place().field_name() {
            fields.entry(read.symbol()).or_default()[0].insert(field);
        }
    }
    for mutation in psm.mutations() {
        if let Some(field) = mutation.target().field_name() {
            fields.entry(mutation.symbol()).or_default()[1].insert(field);
        }
    }
    Some(fields)
}

pub(super) fn symbol_fields(
    psm: &ProgramSemanticModel,
    symbol: &str,
    index: Option<&FieldProjection<'_>>,
) -> [Vec<String>; 2] {
    let reads = index.map_or_else(
        || {
            psm.state_reads()
                .iter()
                .filter(|item| item.symbol() == symbol)
                .filter_map(|item| item.place().field_name().map(str::to_owned))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        },
        |fields| {
            fields.get(symbol).map_or_else(Vec::new, |names| {
                names[0].iter().copied().map(str::to_owned).collect()
            })
        },
    );
    let writes = index.map_or_else(
        || {
            psm.mutations()
                .iter()
                .filter(|item| item.symbol() == symbol)
                .filter_map(|item| item.target().field_name().map(str::to_owned))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        },
        |fields| {
            fields.get(symbol).map_or_else(Vec::new, |names| {
                names[1].iter().copied().map(str::to_owned).collect()
            })
        },
    );
    [reads, writes]
}
