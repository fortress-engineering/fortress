//! Bounded authored Boolean requirements for linked native declarations.

use serde::{Deserialize, Serialize};

use crate::program_semantics::native_body::NativeBodyLanguage;
use crate::program_semantics::native_callable::valid_slot_reference;
use crate::wire::{JsonAdmissionLimits, admit_json, parse_strict_json_bytes};

/// Schema identity for the authored native Boolean contract document.
pub const NATIVE_RETURN_CONTRACT_SCHEMA: &str = "urn:fortress:schema:v1:native-function-contracts";

const MAX_CONTRACTS: usize = 64;
const LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 16 * 1024,
    depth: 4,
    nodes: 768,
    token_bytes: 256,
};

/// A canonical authored set of exact native declaration references.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReturnContracts {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    functions: Vec<NativeReturnContract>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeReturnContract {
    subject: String,
    required_return: bool,
}

/// Why a native return contract could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReturnContractError {
    /// JSON, schema identity, size, or subject selector is outside registered support.
    Invalid,
    /// A supported shape was not encoded in the registered canonical form.
    Noncanonical,
}

impl NativeReturnContracts {
    /// Reads and validates exact canonical authored bytes.
    ///
    /// The record does not confer Module ownership, link a body, or authorize a
    /// change. Snapshot Governance resolves those independent source premises.
    ///
    /// # Errors
    /// Refuses unsupported schemas, excessive input, noncanonical bytes, or
    /// invalid, duplicate, and unordered stable callable references.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, NativeReturnContractError> {
        use NativeReturnContractError::{Invalid, Noncanonical};

        admit_json(bytes, LIMITS).map_err(|_| Invalid)?;
        let document: Self = parse_strict_json_bytes(bytes).map_err(|_| Invalid)?;
        if document.schema != NATIVE_RETURN_CONTRACT_SCHEMA
            || document.schema_version != 1
            || document.functions.is_empty()
            || document.functions.len() > MAX_CONTRACTS
            || document
                .functions
                .windows(2)
                .any(|pair| pair[0].subject >= pair[1].subject)
            || document.functions.iter().any(|item| {
                ![NativeBodyLanguage::Go, NativeBodyLanguage::Python]
                    .into_iter()
                    .any(|language| valid_slot_reference(language, &item.subject))
            })
        {
            return Err(Invalid);
        }
        let canonical = serde_json_canonicalizer::to_vec(&document).map_err(|_| Invalid)?;
        if bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
            return Err(Noncanonical);
        }
        Ok(document)
    }

    /// Returns an explicit requirement for the already resolved native slot.
    #[must_use]
    pub fn required_return(&self, subject: &str) -> Option<bool> {
        self.functions
            .binary_search_by(|item| item.subject.as_str().cmp(subject))
            .ok()
            .map(|index| self.functions[index].required_return)
    }
}
