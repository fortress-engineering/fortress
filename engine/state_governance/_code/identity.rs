//! Separate software and governing identities from the original full-repository binding.
use super::{Axis, StateAssets, TransitionError, digest};
use serde_json::json;
use std::collections::BTreeMap;
fn roles(assets: &StateAssets, source: bool) -> Option<BTreeMap<&str, BTreeMap<Axis, &str>>> {
    let mut result = BTreeMap::new();
    for input in &assets.inputs {
        let selected = input
            .roles
            .iter()
            .filter(|(axis, _)| (**axis == Axis::Subject) == source)
            .map(|(axis, digest)| (*axis, digest.as_str()))
            .collect::<BTreeMap<_, _>>();
        if !selected.is_empty() && result.insert(input.id.as_str(), selected).is_some() {
            return None;
        }
    }
    Some(result)
}
pub(super) fn subject(assets: &StateAssets) -> Result<Option<String>, TransitionError> {
    if !assets.complete_axes.contains(&Axis::Subject) {
        return Ok(None);
    }
    roles(assets, true)
        .map(|inputs| digest(&json!({"domain":"role-partitioned-subject-v1","inputs":inputs})))
        .transpose()
}
pub(super) fn governing(
    assets: &StateAssets,
    context: Option<&str>,
) -> Result<Option<String>, TransitionError> {
    if ![Axis::Intent, Axis::Authority, Axis::Governance]
        .iter()
        .all(|a| assets.complete_axes.contains(a))
        || assets.standard_ref.is_none()
        || assets.evaluator_ref.is_none()
    {
        return Ok(None);
    }
    roles(assets,false).map(|inputs|digest(&json!({"domain":"role-partitioned-governing-v1","inputs":inputs,"standard":assets.standard_ref,"profiles":assets.profile_refs,"evaluator":assets.evaluator_ref,"exclusions":assets.exclusions_ref,"context":context}))).transpose()
}
