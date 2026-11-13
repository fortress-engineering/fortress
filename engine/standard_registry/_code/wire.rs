//! Version negotiation and strict JSON boundary for new public wire records.
//!
//! Existing model owners keep their serializers and historical digest inputs.
//! This boundary is opt-in for public records and can also preflight legacy
//! authored JSON without changing their representation or identity algorithm.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Largest exact unsigned integer in the public IEEE-754 JSON interchange.
pub const MAX_EXACT_PUBLIC_INTEGER: u64 = 9_007_199_254_740_991;

/// Escapes terminal and direction-control characters in an untrusted display field.
/// This changes presentation only; canonical source and machine values are untouched.
#[must_use]
pub fn readable_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_control()
            || matches!(character, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

/// Allocation admission for JSON, independent of the owning semantic decoder.
#[derive(Clone, Copy, Debug)]
pub struct JsonAdmissionLimits {
    /// Maximum UTF-8 input bytes.
    pub bytes: usize,
    /// Maximum simultaneously open arrays and objects.
    pub depth: usize,
    /// Maximum container, key, string, and primitive tokens in the entire input.
    pub nodes: usize,
    /// Maximum encoded bytes in any single string or primitive token.
    pub token_bytes: usize,
}

/// Includes large canonical projections; narrower ingress owners retain their quotas.
pub const JSON_ADMISSION_LIMITS: JsonAdmissionLimits = JsonAdmissionLimits {
    bytes: 512 * 1024 * 1024,
    depth: 96,
    nodes: 16_000_000,
    token_bytes: 32 * 1024 * 1024,
};

/// Checks allocation budgets before a JSON library constructs strings or trees.
///
/// This is a resource scan, not a second JSON validator. Malformed syntax still
/// goes to the existing strict decoder. Nothing is truncated or accepted early.
///
/// # Errors
/// Returns a `RESOURCE_LIMIT` error if any admission budget is exceeded.
pub fn admit_json(source: &[u8], limits: JsonAdmissionLimits) -> Result<(), serde_json::Error> {
    let exhausted = || {
        <serde_json::Error as de::Error>::custom("RESOURCE_LIMIT: JSON admission quota exceeded")
    };
    if source.len() > limits.bytes {
        return Err(exhausted());
    }
    let (mut depth, mut nodes, mut position) = (0_usize, 0_usize, 0_usize);
    while position < source.len() {
        let byte = source[position];
        if byte.is_ascii_whitespace() || matches!(byte, b',' | b':' | b'}' | b']') {
            if matches!(byte, b'}' | b']') {
                depth = depth.saturating_sub(1);
            }
            position += 1;
            continue;
        }
        nodes = nodes.checked_add(1).ok_or_else(exhausted)?;
        if nodes > limits.nodes {
            return Err(exhausted());
        }
        if matches!(byte, b'{' | b'[') {
            depth += 1;
            if depth > limits.depth {
                return Err(exhausted());
            }
            position += 1;
        } else {
            let start = position;
            position += 1;
            if byte == b'"' {
                let mut escaped = false;
                while position < source.len() {
                    let next = source[position];
                    position += 1;
                    if !escaped && next == b'"' {
                        break;
                    }
                    escaped = !escaped && next == b'\\';
                    if position - start > limits.token_bytes {
                        return Err(exhausted());
                    }
                }
            } else {
                while position < source.len()
                    && !source[position].is_ascii_whitespace()
                    && !matches!(
                        source[position],
                        b',' | b':' | b'}' | b']' | b'{' | b'[' | b'"'
                    )
                {
                    position += 1;
                }
            }
            if position - start > limits.token_bytes {
                return Err(exhausted());
            }
        }
    }
    Ok(())
}

/// Reader decision for an exact schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionDecision {
    /// The reader implements this version directly.
    Accepted,
    /// The version needs an explicit, separately qualified migration.
    RequiresMigration,
    /// Neither a reader nor a migration is advertised.
    Unsupported,
}

/// Enumerates versions accepted by one concrete reader boundary.
#[derive(Clone, Copy, Debug)]
pub struct VersionSupport<'a> {
    accepted: &'a [u16],
    requires_migration: &'a [u16],
}

impl<'a> VersionSupport<'a> {
    /// Creates a reader declaration; this does not infer adjacent versions.
    #[must_use]
    pub const fn new(accepted: &'a [u16], requires_migration: &'a [u16]) -> Self {
        Self {
            accepted,
            requires_migration,
        }
    }

    /// Resolves one exact version without an optimistic fallback.
    #[must_use]
    pub fn resolve(self, version: u16) -> VersionDecision {
        if self.accepted.contains(&version) {
            VersionDecision::Accepted
        } else if self.requires_migration.contains(&version) {
            VersionDecision::RequiresMigration
        } else {
            VersionDecision::Unsupported
        }
    }
}

/// Failure at the JSON wire boundary.
#[derive(Debug)]
pub enum WireError {
    /// A JSON token, duplicate key, or exact-number limit was invalid.
    Json(serde_json::Error),
    /// An integer token cannot be represented exactly by public JSON readers.
    InexactInteger,
    /// Canonicalization failed after strict decoding.
    Canonical(String),
}

impl Display for WireError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid JSON wire record: {error}"),
            Self::InexactInteger => formatter.write_str("integer exceeds exact public JSON range"),
            Self::Canonical(error) => write!(formatter, "JCS serialization failed: {error}"),
        }
    }
}

impl Error for WireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Canonical(_) | Self::InexactInteger => None,
        }
    }
}

/// Decodes a legacy or authored JSON record after rejecting duplicate keys.
///
/// Historical numeric and digest semantics remain with the model owner.
///
/// # Errors
///
/// Returns [`WireError`] for invalid JSON, duplicate keys, or model mismatch.
pub fn parse_strict_json<T: DeserializeOwned>(source: &str) -> Result<T, WireError> {
    reject_duplicate_json_keys(source).map_err(WireError::Json)?;
    serde_json::from_str(source).map_err(WireError::Json)
}

/// Decodes a new public JSON record under exact 53-bit integer limits.
///
/// Values outside the exact range must be represented by a domain-specific
/// canonical decimal-string field in the owning DTO.
///
/// # Errors
///
/// Returns [`WireError`] for invalid JSON, duplicate keys, inexact integers,
/// non-finite numbers, or model mismatch.
pub fn parse_public_json<T: DeserializeOwned>(source: &str) -> Result<T, WireError> {
    admit_json(source.as_bytes(), JSON_ADMISSION_LIMITS).map_err(WireError::Json)?;
    check_public_integer_tokens(source)?;
    validate_structure::<true>(source).map_err(WireError::Json)?;
    serde_json::from_str(source).map_err(WireError::Json)
}

fn check_public_integer_tokens(source: &str) -> Result<(), WireError> {
    let bytes = source.as_bytes();
    let mut position = 0;
    let mut quoted = false;
    let mut escaped = false;
    while position < bytes.len() {
        let byte = bytes[position];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            position += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
            position += 1;
            continue;
        }
        if byte != b'-' && !byte.is_ascii_digit() {
            position += 1;
            continue;
        }
        let start = position;
        position += 1;
        while position < bytes.len()
            && matches!(
                bytes[position],
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
            )
        {
            position += 1;
        }
        let token = &source[start..position];
        if token
            .bytes()
            .any(|value| matches!(value, b'.' | b'e' | b'E'))
        {
            continue;
        }
        let magnitude = token.strip_prefix('-').unwrap_or(token);
        if !matches!(magnitude.parse::<u128>(), Ok(value) if value <= u128::from(MAX_EXACT_PUBLIC_INTEGER))
        {
            return Err(WireError::InexactInteger);
        }
    }
    Ok(())
}

/// Preflights JSON before an existing owner-specific typed reader runs.
///
/// This preserves the owner's typed decoder and historical numeric semantics
/// while preventing duplicate keys from being silently overwritten.
///
/// # Errors
///
/// Returns a JSON error for duplicate keys, malformed input, or non-finite
/// numbers.
pub fn reject_duplicate_json_keys(source: &str) -> Result<(), serde_json::Error> {
    validate_structure::<false>(source)
}

/// Preflights UTF-8 JSON bytes before an existing typed byte-slice reader.
///
/// # Errors
///
/// Returns a JSON error for duplicate keys or malformed input.
pub fn reject_duplicate_json_keys_bytes(source: &[u8]) -> Result<(), serde_json::Error> {
    admit_json(source, JSON_ADMISSION_LIMITS)?;
    let mut parser = serde_json::Deserializer::from_slice(source);
    StrictStructure::<false>::deserialize(&mut parser)?;
    parser.end()
}

/// Decodes legacy or operational JSON bytes after duplicate-key preflight.
///
/// # Errors
///
/// Returns [`WireError`] for invalid JSON, duplicate keys, or model mismatch.
pub fn parse_strict_json_bytes<T: DeserializeOwned>(source: &[u8]) -> Result<T, WireError> {
    reject_duplicate_json_keys_bytes(source).map_err(WireError::Json)?;
    serde_json::from_slice(source).map_err(WireError::Json)
}

/// Canonicalizes a new public JSON record as RFC 8785 JCS UTF-8 bytes.
///
/// This must not be substituted for any historical identity or content hash.
///
/// # Errors
///
/// Returns [`WireError`] for invalid JSON, duplicate keys, inexact integers,
/// or serialization failure.
pub fn canonicalize_public_json(source: &str) -> Result<Vec<u8>, WireError> {
    let value: Value = parse_public_json(source)?;
    serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| WireError::Canonical(error.to_string()))
}

fn validate_structure<const EXACT: bool>(source: &str) -> Result<(), serde_json::Error> {
    admit_json(source.as_bytes(), JSON_ADMISSION_LIMITS)?;
    let mut parser = serde_json::Deserializer::from_str(source);
    StrictStructure::<EXACT>::deserialize(&mut parser)?;
    parser.end()
}

struct StrictStructure<const EXACT: bool>;

impl<'de, const EXACT: bool> Deserialize<'de> for StrictStructure<EXACT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StructureVisitor::<EXACT>)?;
        Ok(Self)
    }
}

struct StructureVisitor<const EXACT: bool>;

impl<'de, const EXACT: bool> Visitor<'de> for StructureVisitor<EXACT> {
    type Value = ();

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_string<E: de::Error>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if EXACT && value.unsigned_abs() > MAX_EXACT_PUBLIC_INTEGER {
            return Err(E::custom("integer exceeds exact public JSON range"));
        }
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        if EXACT && value > MAX_EXACT_PUBLIC_INTEGER {
            return Err(E::custom("integer exceeds exact public JSON range"));
        }
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        if !value.is_finite() {
            return Err(E::custom("non-finite JSON number"));
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        while sequence.next_element::<StrictStructure<EXACT>>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key `{}`",
                    key.chars()
                        .flat_map(char::escape_default)
                        .take(128)
                        .collect::<String>()
                )));
            }
            map.next_value::<StrictStructure<EXACT>>()?;
        }
        Ok(())
    }
}
