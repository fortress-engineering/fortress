//! Original-authority comparison of an admitted native return.

use crate::affected_analysis::sha256;
use crate::native_observation::NativeSource;
use crate::program_semantics::native_callable::{LinkedNativeCallable, NativeCallableOutcome};
use crate::semantic_analysis::{
    NativeBooleanReturn, NativeReturnContracts, compare_native_boolean_return,
};

/// The exact callable observation and a separately selected authored comparison.
#[derive(Debug)]
pub struct AuthoredNativeReturnObservation {
    /// Typed native scope, precise body linkage or explicit limitation.
    pub subject: NativeCallableOutcome,
    /// The separately bound authored observation.
    pub comparison: AuthoredNativeReturnComparison,
}

/// Result of resolving an authored requirement in original Module territory.
#[derive(Debug)]
pub enum AuthoredNativeReturnComparison {
    /// The exact original requirement was selected and its Boolean bound compared.
    Observed(BoundNativeReturnComparison),
    /// The known inputs cannot establish the requested authored comparison.
    Unavailable(NativeReturnComparisonLimitation),
}

/// Exact authored evidence alongside the bounded native result comparison.
#[derive(Debug)]
pub struct BoundNativeReturnComparison {
    /// Original Module that owns both the requirement and admitted declaration.
    pub author: String,
    /// Exact path of the original authored document.
    pub contract_path: String,
    /// SHA-256 of the exact authored document.
    pub contract_ref: String,
    /// The required Boolean result from the original authored document.
    pub required_return: bool,
    /// Relation of the observed static bound to the original requirement.
    pub observed_return: NativeBooleanReturn,
}

/// Why the original inputs cannot establish a comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReturnComparisonLimitation {
    /// The actual observations did not establish a unique callable body.
    SubjectUnavailable,
    /// An independently declared logical source owner is required.
    OwnerUnavailable,
    /// The artifact population or its selected territory is outside supported scope.
    UnsupportedContractScope,
    /// At least one captured authored document is malformed, empty or noncanonical.
    InvalidContractDocument,
    /// No original document contains this exact slot reference.
    RequirementUnavailable,
    /// A purported requirement belongs to another Module.
    ForeignContractOwner,
    /// More than one supported original artifact supplies the slot.
    AmbiguousRequirement,
}

pub(crate) fn compare_captured_native_return(
    source: &NativeSource<'_>,
    subject: NativeCallableOutcome,
) -> AuthoredNativeReturnObservation {
    let comparison = match &subject {
        NativeCallableOutcome::Linked(link) => compare_link(source, link).map_or_else(
            AuthoredNativeReturnComparison::Unavailable,
            AuthoredNativeReturnComparison::Observed,
        ),
        NativeCallableOutcome::Unavailable(_) => AuthoredNativeReturnComparison::Unavailable(
            NativeReturnComparisonLimitation::SubjectUnavailable,
        ),
    };
    AuthoredNativeReturnObservation {
        subject,
        comparison,
    }
}

fn compare_link(
    source: &NativeSource<'_>,
    link: &LinkedNativeCallable,
) -> Result<BoundNativeReturnComparison, NativeReturnComparisonLimitation> {
    use NativeReturnComparisonLimitation as Limit;

    let owner = link
        .declared_source_owner()
        .ok_or(Limit::OwnerUnavailable)?;
    let contracts = &source.binding.native_return_contracts;
    if contracts.len() > 64 {
        return Err(Limit::UnsupportedContractScope);
    }
    let mut selected = None;
    for contract in contracts {
        let path = contract.path();
        if !path.ends_with("/data/native_function_contracts.json") {
            return Err(Limit::UnsupportedContractScope);
        }
        let bytes = source
            .view
            .bytes(path)
            .ok_or(Limit::InvalidContractDocument)?;
        let document = NativeReturnContracts::from_canonical_bytes(bytes)
            .map_err(|_| Limit::InvalidContractDocument)?;
        if let Some(expected) = document.required_return(link.slot_ref()) {
            if selected.is_some() {
                return Err(Limit::AmbiguousRequirement);
            }
            selected = Some((contract, bytes, expected));
        }
    }
    let (contract, bytes, required_return) = selected.ok_or(Limit::RequirementUnavailable)?;
    if contract.module() != owner.owner() {
        return Err(Limit::ForeignContractOwner);
    }
    Ok(BoundNativeReturnComparison {
        author: owner.owner().into(),
        contract_path: contract.path().into(),
        contract_ref: sha256(bytes),
        required_return,
        observed_return: compare_native_boolean_return(link.body(), required_return),
    })
}
