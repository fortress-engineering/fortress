//! Lossless public projection of existing native comparison inputs.
//! Native identities and historical payloads are preserved; current public `StateView` versions
//! are projected directly, without claiming standalone schema conformance of a native frame.
use super::{ComparisonState, MAX_TRANSITION_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    state_ref: String,
    native_schema: String,
    native_schema_version: u16,
    native_schema_conformance: String,
    canonical_native_chunks: Vec<String>,
    source_ref: Option<String>,
    view: Value,
    retained_application: Value,
    assets: Value,
    origin_ref: Option<String>,
    limitations: Vec<String>,
}
impl Projection {
    fn from_state(state: &ComparisonState) -> Result<Self, String> {
        let bytes = state.to_canonical_bytes().map_err(|e| e.to_string())?;
        let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
        let mut chunks = Vec::new();
        let mut offset = 0usize;
        while offset < text.len() {
            let mut end = offset.saturating_add(2048).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            chunks.push(text[offset..end].to_owned());
            offset = end;
        }
        Ok(Self {
            schema: "urn:fortress:derived:v1:comparison-projection".into(),
            schema_version: 1,
            state_ref: state.digest().map_err(|e| e.to_string())?,
            native_schema: state.schema.clone(),
            native_schema_version: state.schema_version,
            native_schema_conformance: "NOT_ASSERTED_NATIVE_OWNER_VALIDATED".into(),
            canonical_native_chunks: chunks,
            source_ref: state.source_ref.clone(),
            view: serde_json::to_value(&state.view).map_err(|e| e.to_string())?,
            retained_application: serde_json::to_value(&state.retained_application)
                .map_err(|e| e.to_string())?,
            assets: serde_json::to_value(&state.assets).map_err(|e| e.to_string())?,
            origin_ref: state.origin_ref.clone(),
            limitations: state.limitations.clone(),
        })
    }
    fn into_state(self) -> Result<ComparisonState, String> {
        if self.schema != "urn:fortress:derived:v1:comparison-projection"
            || self.schema_version != 1
            || self.canonical_native_chunks.len() > MAX_TRANSITION_BYTES / 1024 + 1
            || self
                .canonical_native_chunks
                .iter()
                .any(|c| c.is_empty() || c.len() > 2048)
            || self
                .canonical_native_chunks
                .iter()
                .map(String::len)
                .sum::<usize>()
                > MAX_TRANSITION_BYTES
        {
            return Err("Unsupported or excessive comparison projection".into());
        }
        let native = self.canonical_native_chunks.concat();
        let state = ComparisonState::from_json_str(&native).map_err(|e| e.to_string())?;
        let expected = Self::from_state(&state)?;
        if serde_json::to_value(&self).map_err(|e| e.to_string())?
            != serde_json::to_value(&expected).map_err(|e| e.to_string())?
        {
            return Err("Comparison projection does not preserve exact native bytes, identity and owner facts".into());
        }
        Ok(state)
    }
}
/// Serializes the unchanged native identity plus independently readable public owner facts.
/// # Errors
/// Refuses invalid native input or serialization failure.
pub fn serialize<S: serde::Serializer>(
    state: &ComparisonState,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Projection::from_state(state)
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}
/// Restores only an exact existing-owner-validated native input, never a grant or evaluator.
/// # Errors
/// Refuses altered projections, unsupported versions, malformed native inputs and resource limits.
pub fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<ComparisonState, D::Error> {
    Projection::deserialize(deserializer)?
        .into_state()
        .map_err(serde::de::Error::custom)
}
/// Bounded sequences use the same exact frame rather than rewriting historical identities.
pub mod sequence {
    use super::{ComparisonState, Deserialize, Projection, Serialize};
    /// Serializes original inputs as separate lossless projections.
    /// # Errors
    /// Refuses invalid or excessive original inputs.
    pub fn serialize<S: serde::Serializer>(
        states: &[ComparisonState],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let projections = states
            .iter()
            .map(Projection::from_state)
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde::ser::Error::custom)?;
        projections.serialize(serializer)
    }
    /// Reads exact existing-owner inputs without silently normalizing their wire versions.
    /// # Errors
    /// Refuses excessive, malformed or inconsistent originals.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<ComparisonState>, D::Error> {
        let projections = Vec::<Projection>::deserialize(deserializer)?;
        if projections.len() > 16 {
            return Err(serde::de::Error::custom(
                "historical projection count exceeds admission",
            ));
        }
        projections
            .into_iter()
            .map(|p| p.into_state().map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Optional original endpoints retain their exact native identity and public owner facts.
pub mod optional {
    use super::{ComparisonState, Deserialize, Projection, Serialize};
    /// Serializes an optional immutable original input.
    /// # Errors
    /// Refuses malformed native input and serializer errors.
    pub fn serialize<S: serde::Serializer>(
        state: &Option<ComparisonState>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        state
            .as_ref()
            .map(Projection::from_state)
            .transpose()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    /// Restores an optional original without rewriting its version or granting authority.
    /// # Errors
    /// Refuses malformed or inconsistent projected input.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ComparisonState>, D::Error> {
        Option::<Projection>::deserialize(deserializer)?
            .map(Projection::into_state)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}
