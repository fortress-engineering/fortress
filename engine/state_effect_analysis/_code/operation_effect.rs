//! Canonical positive classification facts from the installed operation catalog.

use super::OperationSummaryCatalog;
use crate::semantic_analysis::FunctionEffect;

/// Positive lower facts; absence is never a complete upper bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OperationEffectClassification {
    /// The exact external boundary has retained positive modeled effects.
    Supported(Vec<FunctionEffect>),
    /// The catalog has no positive modeled effect at this boundary.
    NoOperationalEffect,
    /// No installed record accounts for this external operation.
    Unsupported,
}

/// Dispatches PSM-established identities without a second purity table.
pub(super) fn classify_operation(
    catalog: &OperationSummaryCatalog,
    operation: &str,
) -> OperationEffectClassification {
    if !catalog
        .summaries()
        .iter()
        .any(|summary| summary.operation_selector == operation)
    {
        return OperationEffectClassification::Unsupported;
    }
    let effects = catalog.observed_effects(operation);
    if effects.is_empty() {
        if catalog.summaries().iter().any(|summary| {
            summary.operation_selector == operation
                && summary.authority_class != super::SummaryAuthorityClass::Assumed
                && summary
                    .qualification_refs
                    .iter()
                    .any(|reference| reference.starts_with("legacy-classifier:"))
        }) {
            OperationEffectClassification::NoOperationalEffect
        } else {
            OperationEffectClassification::Unsupported
        }
    } else {
        OperationEffectClassification::Supported(effects)
    }
}
