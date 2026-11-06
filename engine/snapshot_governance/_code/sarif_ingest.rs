//! Bounded streaming SARIF2.1 observations; tool output never decides conformance.

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Formatter};

use crate::provider::{
    EvidenceEnvelope, InventoryKey, InventoryNamespace, InvocationBasis, InvocationOutcome,
    MAX_PROVIDER_RECORDS, NormalizedBudget, ProviderError, ProviderFormat, ProviderObservation,
    ProviderOutcome, ProviderRunManifest, ensure, hash, preflight_json,
};

/// Structural address of the supported single SARIF run and invocation.
pub(super) const INVOCATION_SCOPE: &str = "run:0/invocation:0";

struct Limited<T, const N: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for Limited<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ArrayVisitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ArrayVisitor<T, N> {
            type Value = Limited<T, N>;
            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded SARIF sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut result = Vec::new();
                while let Some(value) = seq.next_element()? {
                    if result.len() >= N {
                        return Err(serde::de::Error::custom("SARIF array/scope limit"));
                    }
                    result.push(value);
                }
                Ok(Limited(result))
            }
        }
        d.deserialize_seq(ArrayVisitor(std::marker::PhantomData))
    }
}
#[derive(Default)]
struct NonEmpty(bool);
impl<'de> Deserialize<'de> for NonEmpty {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = NonEmpty;
            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded SARIF reference object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut count = 0_usize;
                while map.next_key::<IgnoredAny>()?.is_some() {
                    count += 1;
                    if count > MAX_PROVIDER_RECORDS {
                        return Err(serde::de::Error::custom("SARIF object limit"));
                    }
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(NonEmpty(count > 0))
            }
        }
        d.deserialize_map(ObjectVisitor)
    }
}
#[derive(Deserialize)]
struct Document {
    version: String,
    runs: Limited<Run, 1>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    results: Option<Limited<ResultRow, MAX_PROVIDER_RECORDS>>,
    invocations: Option<Limited<Invocation, 1>>,
    external_property_file_references: Option<NonEmpty>,
}
#[derive(Deserialize)]
struct Tool {
    driver: Driver,
    extensions: Option<Limited<IgnoredAny, MAX_PROVIDER_RECORDS>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: String,
    version: Option<String>,
    semantic_version: Option<String>,
    rules: Option<Limited<Rule, MAX_PROVIDER_RECORDS>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    default_configuration: Option<RuleConfiguration>,
}
#[derive(Deserialize)]
struct RuleConfiguration {
    enabled: Option<bool>,
    level: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: Option<bool>,
    exit_code: Option<i32>,
    tool_execution_notifications: Option<Limited<Notification, MAX_PROVIDER_RECORDS>>,
    tool_configuration_notifications: Option<Limited<Notification, MAX_PROVIDER_RECORDS>>,
    rule_configuration_overrides: Option<Limited<IgnoredAny, MAX_PROVIDER_RECORDS>>,
}
#[derive(Deserialize)]
struct Notification {
    level: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResultRow {
    rule_id: Option<String>,
    rule_index: Option<u64>,
    rule: Option<RuleReference>,
    kind: Option<String>,
    baseline_state: Option<String>,
    suppressions: Option<Limited<IgnoredAny, MAX_PROVIDER_RECORDS>>,
    guid: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleReference {
    id: Option<String>,
    index: Option<u64>,
    tool_component: Option<NonEmpty>,
}
#[derive(Default)]
struct RuleFacts {
    failures: u64,
    not_applicable: bool,
    unknown: bool,
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 65_536 && !value.chars().any(char::is_control)
}
fn malformed(detail: &str) -> ProviderError {
    ProviderError::Invalid(detail.into())
}

#[allow(clippy::too_many_lines)]
pub(super) fn parse(
    payload: &[u8],
    manifest: Option<ProviderRunManifest>,
) -> Result<EvidenceEnvelope, ProviderError> {
    preflight_json(payload)?;
    let source =
        std::str::from_utf8(payload).map_err(|_| malformed("SARIF requires UTF-8 JSON"))?;
    // Independent structure-only traversal checks duplicates and numeric exactness
    // everywhere, including skipped extension properties, without a Value tree.
    let _: IgnoredAny = crate::wire::parse_public_json(source)
        .map_err(|_| malformed("malformed/duplicate/inexact SARIF JSON"))?;
    let document: Document = serde_json::from_str(source).map_err(|e| {
        if e.to_string().contains("SARIF array/scope limit")
            || e.to_string().contains("SARIF object limit")
        {
            ProviderError::ResourceLimit("SARIF arrays/scope")
        } else {
            malformed("unsupported or malformed SARIF structure")
        }
    })?;
    ensure(document.version == "2.1.0", "unsupported SARIF version")?;
    if let Some(m) = &manifest {
        m.validate()?;
        ensure(
            m.invocation_scope == INVOCATION_SCOPE,
            "SARIF manifest must select its exact structural invocation scope",
        )?;
    }
    let Some(run) = document.runs.0.into_iter().next() else {
        ensure(
            manifest.is_none(),
            "companion declares an unavailable SARIF run",
        )?;
        return EvidenceEnvelope::compose(
            ProviderFormat::Sarif210,
            None,
            None,
            hash(payload),
            None,
            vec![],
            InvocationOutcome::default(),
            InvocationBasis::Unknown,
            vec!["SARIF_RUN_UNAVAILABLE".into()],
        );
    };
    ensure(
        valid_text(&run.tool.driver.name),
        "invalid SARIF tool identity",
    )?;
    let version = run
        .tool
        .driver
        .semantic_version
        .as_ref()
        .or(run.tool.driver.version.as_ref());
    if let Some(version) = version {
        ensure(valid_text(version), "invalid SARIF tool version")?;
    }
    let mut limitations = BTreeSet::new();
    if version.is_none() {
        limitations.insert("SARIF_TOOL_VERSION_UNAVAILABLE".into());
    }
    if run
        .external_property_file_references
        .as_ref()
        .is_some_and(|r| r.0)
    {
        limitations.insert("SARIF_EXTERNAL_PROPERTIES_UNRESOLVED".into());
    }
    if run
        .tool
        .extensions
        .as_ref()
        .is_some_and(|r| !r.0.is_empty())
    {
        limitations.insert("SARIF_TOOL_EXTENSIONS_UNINTERPRETED".into());
    }
    let invocation = run.invocations.as_ref().and_then(|i| i.0.first());
    let mut outcome = invocation.map_or_else(InvocationOutcome::default, |i| InvocationOutcome {
        succeeded: i.execution_successful,
        exit_code: i.exit_code,
    });
    if let Some(invocation) = invocation {
        if invocation
            .tool_execution_notifications
            .iter()
            .chain(&invocation.tool_configuration_notifications)
            .flat_map(|n| &n.0)
            .any(|n| n.level.as_deref() == Some("error"))
        {
            outcome.succeeded = Some(false);
        }
        if invocation
            .rule_configuration_overrides
            .as_ref()
            .is_some_and(|r| !r.0.is_empty())
        {
            limitations.insert("SARIF_RULE_OVERRIDES_UNINTERPRETED".into());
        }
    } else {
        limitations.insert("SARIF_INVOCATION_SCOPE_UNRESOLVED".into());
    }
    if outcome.succeeded.is_none() {
        limitations.insert("SARIF_INVOCATION_STATUS_UNAVAILABLE".into());
    }
    let basis = if outcome == InvocationOutcome::default() {
        InvocationBasis::Unknown
    } else {
        InvocationBasis::Payload
    };
    let rules = run
        .tool
        .driver
        .rules
        .as_ref()
        .map(|r| r.0.as_slice())
        .unwrap_or_default();
    if run.tool.driver.rules.is_none() {
        limitations.insert("SARIF_RULE_CATALOG_UNAVAILABLE".into());
    }
    let mut rule_ids = BTreeSet::new();
    let mut facts = BTreeMap::<&str, RuleFacts>::new();
    for rule in rules {
        ensure(
            valid_text(&rule.id) && rule_ids.insert(rule.id.as_str()),
            "duplicate/invalid SARIF rule identity",
        )?;
        if rule
            .default_configuration
            .as_ref()
            .is_some_and(|c| c.enabled == Some(false) || c.level.as_deref() == Some("none"))
        {
            limitations.insert("SARIF_DISABLED_RULE".into());
        }
    }
    let results = run
        .results
        .as_ref()
        .map(|r| r.0.as_slice())
        .unwrap_or_default();
    if run.results.is_none() {
        limitations.insert("SARIF_RESULTS_UNAVAILABLE".into());
    }
    let mut result_guids = BTreeSet::new();
    for result in results {
        if let Some(guid) = &result.guid {
            ensure(
                valid_text(guid) && result_guids.insert(guid),
                "duplicate/invalid SARIF result GUID",
            )?;
        }
        let reference = result.rule.as_ref();
        if reference
            .and_then(|r| r.tool_component.as_ref())
            .is_some_and(|r| r.0)
        {
            limitations.insert("SARIF_EXTERNAL_RULE_COMPONENT_UNINTERPRETED".into());
            continue;
        }
        let mut id = result.rule_id.as_deref();
        let mut index = result.rule_index;
        if let Some(reference) = reference {
            if let Some(reference_id) = reference.id.as_deref() {
                ensure(
                    id.is_none_or(|id| id == reference_id),
                    "SARIF rule reference/ID conflict",
                )?;
                id = Some(reference_id);
            }
            if let Some(reference_index) = reference.index {
                ensure(
                    index.is_none_or(|i| i == reference_index),
                    "SARIF rule reference/index conflict",
                )?;
                index = Some(reference_index);
            }
        }
        if let Some(index) = index {
            ensure(
                index <= crate::wire::MAX_EXACT_PUBLIC_INTEGER,
                "inexact SARIF rule index",
            )?;
            let index = usize::try_from(index)
                .map_err(|_| malformed("SARIF rule index exceeds supported range"))?;
            let rule = rules
                .get(index)
                .ok_or_else(|| malformed("SARIF rule index is outside driver catalog"))?;
            ensure(
                id.is_none_or(|id| id == rule.id),
                "SARIF rule ID/index conflict",
            )?;
            id = Some(&rule.id);
        }
        let Some(id) = id else {
            limitations.insert("SARIF_RESULT_RULE_UNRESOLVED".into());
            continue;
        };
        ensure(valid_text(id), "invalid SARIF result rule identity")?;
        if run.tool.driver.rules.is_some() && !rule_ids.contains(id) {
            limitations.insert("SARIF_RESULT_RULE_UNREGISTERED".into());
        }
        let fact = facts.entry(id).or_default();
        if result
            .suppressions
            .as_ref()
            .is_some_and(|s| !s.0.is_empty())
        {
            limitations.insert("SARIF_SUPPRESSED_RESULTS".into());
            fact.unknown = true;
        }
        if result.baseline_state.as_deref() == Some("absent") {
            limitations.insert("SARIF_NONCURRENT_BASELINE_RESULT".into());
            fact.unknown = true;
            continue;
        }
        match result.kind.as_deref().unwrap_or("fail") {
            "fail" => fact.failures += 1,
            "pass" => {}
            "notApplicable" => fact.not_applicable = true,
            _ => {
                fact.unknown = true;
                limitations.insert("SARIF_RESULT_REQUIRES_INTERPRETATION".into());
            }
        }
    }
    let mut budget = NormalizedBudget::default();
    let mut rows = Vec::new();
    let tool = run.tool.driver.name.as_str();
    let current_complete =
        outcome.succeeded == Some(true) && run.results.is_some() && limitations.is_empty();
    if let Some(m) = &manifest {
        ensure(
            m.provider == tool,
            "SARIF companion tool differs from raw driver",
        )?;
        if let Some(version) = version {
            ensure(
                m.provider_version == *version,
                "SARIF companion version differs from raw driver",
            )?;
        }
        for member in &m.inventory {
            ensure(
                member.key.namespace == InventoryNamespace::NativeQualified
                    && member.key.package.as_deref() == Some(tool)
                    && member.key.target.as_deref() == Some(INVOCATION_SCOPE),
                "SARIF companion tool/rule/invocation scope",
            )?;
            if run.tool.driver.rules.is_some() {
                ensure(
                    rule_ids.contains(member.key.qualified_name.as_str()),
                    "SARIF companion rule is not in raw catalog",
                )?;
            }
            member.key.charge(&mut budget)?;
            let fact = facts.get(member.key.qualified_name.as_str());
            let failures = fact.map_or(0, |f| f.failures);
            let result = if failures > 0 {
                ProviderOutcome::Failed
            } else if fact.is_some_and(|f| f.unknown) {
                ProviderOutcome::Unknown
            } else if fact.is_some_and(|f| f.not_applicable) {
                ProviderOutcome::NotApplicable
            } else if current_complete {
                ProviderOutcome::Passed
            } else {
                ProviderOutcome::Unknown
            };
            rows.push(ProviderObservation {
                key: member.key.clone(),
                outcome: result,
                attempts: None,
                retry_metadata_present: false,
                finding_count: if run.results.is_some() {
                    Some(failures)
                } else {
                    None
                },
            });
        }
    } else {
        // No independent inventory means no synthesized absence rows.
        for (id, fact) in &facts {
            if fact.failures == 0 {
                continue;
            }
            budget.charge(256)?;
            budget.text(tool)?;
            budget.text(id)?;
            rows.push(ProviderObservation {
                key: InventoryKey {
                    namespace: InventoryNamespace::NativeQualified,
                    package: Some(tool.into()),
                    target: invocation.map(|_| INVOCATION_SCOPE.into()),
                    qualified_name: (*id).into(),
                },
                outcome: ProviderOutcome::Failed,
                attempts: None,
                retry_metadata_present: false,
                finding_count: Some(fact.failures),
            });
        }
    }
    let provider = Some(run.tool.driver.name.clone());
    let provider_version = version
        .cloned()
        .or_else(|| manifest.as_ref().map(|m| m.provider_version.clone()));
    EvidenceEnvelope::compose(
        ProviderFormat::Sarif210,
        provider,
        provider_version,
        hash(payload),
        manifest,
        rows,
        outcome,
        basis,
        limitations.into_iter().collect(),
    )
}
