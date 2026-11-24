//! Scoped authored policy context for already modeled native operation sites.

use serde::Serialize;

use super::{EffectiveEffectDecision, EffectivePolicy, compile_effective_policy};
use crate::contract_coherency::ModuleSemanticPolicy;
use crate::semantic_analysis::FunctionEffect;
use crate::state_effect_analysis::{
    HypotheticalPythonFilesystemProjection, NativeFilesystemDisposition, NativeFilesystemOperation,
    NativeFilesystemProjection, registered_effect_catalog,
};

/// Authored policy context for modeled sites in one exact native filesystem report.
///
/// The caller establishes original ownership, policy, and source binding before
/// this projection. Reachability is unknown. The result confers no permissions
/// and supplies no assessment, finding, or evidence of effect absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct NativeFilesystemPolicyProjection {
    authored_policy: &'static str,
    effect_registry_sha256: Option<String>,
    reachability: &'static str,
    sites: Vec<NativeFilesystemPolicySite>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct NativeFilesystemPolicySite {
    start_byte: usize,
    end_byte: usize,
    operation: NativeFilesystemOperation,
    effects: Vec<NativeFilesystemPolicyEffect>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct NativeFilesystemPolicyEffect {
    effect: FunctionEffect,
    disposition: NativeFilesystemPolicyDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
enum NativeFilesystemPolicyDisposition {
    Authored { decision: EffectiveEffectDecision },
    Undeclared,
    NoAuthoredPolicy,
    UnregisteredEffect,
}

/// Describes the original Module's policy disposition for each modeled site.
///
/// Local, unresolved, and unsupported sites stay in the input observation and
/// contribute no rows. An empty result makes no claim about other effects.
#[must_use]
pub(crate) fn project_native_filesystem_policy(
    observation: &NativeFilesystemProjection<'_>,
    original_policy: Option<&ModuleSemanticPolicy>,
) -> NativeFilesystemPolicyProjection {
    let compiled = original_policy
        .map(|policy| compile_effective_policy(policy, &registered_effect_catalog()));
    let mut sites = Vec::new();
    for site in observation.sites() {
        let NativeFilesystemDisposition::ModeledOperation {
            operation, effects, ..
        } = site.disposition()
        else {
            continue;
        };
        let range = site.byte_range();
        sites.push(describe_site(
            [range.start, range.end],
            *operation,
            effects,
            compiled.as_ref(),
        ));
    }
    NativeFilesystemPolicyProjection {
        authored_policy: if original_policy.is_some() {
            "PRESENT"
        } else {
            "ABSENT"
        },
        effect_registry_sha256: compiled.map(|policy| policy.registry_digest().to_owned()),
        reachability: "UNKNOWN",
        sites,
    }
}

/// Original policy at a single operation under the closed Python model.
#[derive(Serialize)]
pub(crate) struct HypotheticalPythonFilesystemPolicyProjection {
    scope: &'static str,
    authored_policy: &'static str,
    effect_registry_sha256: Option<String>,
    site: NativeFilesystemPolicySite,
}

/// Describes policy only where the conditional catalog decision models the site.
pub(crate) fn project_hypothetical_python_filesystem_policy(
    observation: &HypotheticalPythonFilesystemProjection<'_>,
    original_policy: Option<&ModuleSemanticPolicy>,
) -> Option<HypotheticalPythonFilesystemPolicyProjection> {
    let NativeFilesystemDisposition::ModeledOperation {
        operation, effects, ..
    } = observation.catalog_disposition()
    else {
        return None;
    };
    let compiled = original_policy
        .map(|policy| compile_effective_policy(policy, &registered_effect_catalog()));
    let site = describe_site(observation.site(), *operation, effects, compiled.as_ref());
    Some(HypotheticalPythonFilesystemPolicyProjection {
        scope: "HYPOTHETICAL_CLOSED_REFERENCE_ONLY",
        authored_policy: if original_policy.is_some() {
            "PRESENT"
        } else {
            "ABSENT"
        },
        effect_registry_sha256: compiled.map(|policy| policy.registry_digest().to_owned()),
        site,
    })
}

fn describe_site(
    [start_byte, end_byte]: [usize; 2],
    operation: NativeFilesystemOperation,
    effects: &[FunctionEffect],
    policy: Option<&EffectivePolicy>,
) -> NativeFilesystemPolicySite {
    NativeFilesystemPolicySite {
        start_byte,
        end_byte,
        operation,
        effects: effects
            .iter()
            .map(|&effect| NativeFilesystemPolicyEffect {
                effect,
                disposition: inspect_effect(effect, policy),
            })
            .collect(),
    }
}

fn inspect_effect(
    effect: FunctionEffect,
    policy: Option<&EffectivePolicy>,
) -> NativeFilesystemPolicyDisposition {
    let Some(policy) = policy else {
        return NativeFilesystemPolicyDisposition::NoAuthoredPolicy;
    };
    match policy
        .decisions()
        .iter()
        .find(|decision| decision.effect() == effect.stable_id())
    {
        Some(decision) if decision.disposition().is_some() => {
            NativeFilesystemPolicyDisposition::Authored {
                decision: decision.clone(),
            }
        }
        Some(_) => NativeFilesystemPolicyDisposition::Undeclared,
        None => NativeFilesystemPolicyDisposition::UnregisteredEffect,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::contract_coherency::ModuleContract;
    use crate::program_semantics::ContextKnowledge;
    use crate::state_effect_analysis::{
        NativeFilesystemBatch, NativeFilesystemBinding, NativeFilesystemCall,
        NativeFilesystemCallee, NativeFilesystemLanguage, SummaryContext, SummaryEffectBound,
        project_native_filesystem_effects,
    };

    const SOURCE: &[u8] = b"package fixture\nimport \"os\"\nfunc Write() { os.WriteFile(\"owned\", nil, 0600) }\nfunc Probe() { local(); dynamic(); os.WriteFile(\"other\", nil, 0600) }\n";
    const BINDING_REF: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const BINDING: NativeFilesystemBinding<'static> = NativeFilesystemBinding {
        snapshot_fingerprint: BINDING_REF,
        source_view_sha256: BINDING_REF,
        authority_sha256: BINDING_REF,
        evaluation_sha256: BINDING_REF,
        source_path: "fixture.go",
        source_sha256: "sha256:032a9465733a072cbe7bc5b0d1f4f52f6dfc9471cb90c12c82338584052bb690",
    };

    fn with_observation(test: impl FnOnce(&NativeFilesystemProjection<'_>)) {
        let known = SummaryContext {
            source_digest: ContextKnowledge::Known(
                "sha256:f303ff6f8d3d1c289200cd4ec875383db41fa256582cf573e9e24cd02043523f".into(),
            ),
            version: ContextKnowledge::Known("go1.22.2".into()),
            target: ContextKnowledge::Known("linux/amd64".into()),
            features: ContextKnowledge::Known(vec!["cgo-disabled".into(), "local-stdlib".into()]),
            type_bindings: ContextKnowledge::Known(Vec::new()),
        };
        let uncertain = SummaryContext {
            version: ContextKnowledge::Unknown,
            ..known.clone()
        };
        let call = |start_byte, end_byte, callee| NativeFilesystemCall {
            start_byte,
            end_byte,
            callee,
        };
        let standard = |summary_context| NativeFilesystemCallee::ResolvedStandardLibrary {
            operation: NativeFilesystemOperation::GoOsWriteFile,
            declaration_sha256: BINDING_REF,
            summary_context,
        };
        let batch = NativeFilesystemBatch {
            language: NativeFilesystemLanguage::Go,
            binding: BINDING,
            observation_sha256: BINDING_REF,
            calls: &[
                call(43, 75, standard(&known)),
                call(93, 100, NativeFilesystemCallee::LocalOrShadowed),
                call(102, 111, NativeFilesystemCallee::Unresolved),
                call(113, 145, standard(&uncertain)),
            ],
        };
        let observation = project_native_filesystem_effects(BINDING, SOURCE, &batch).unwrap();
        assert_eq!(observation.upper_bound(), &SummaryEffectBound::Unknown);
        test(&observation);
    }

    fn contract(
        capability_allow: &[&str],
        capability_deny: &[&str],
        effect_allow: &[&str],
        effect_deny: &[&str],
    ) -> ModuleContract {
        let fixture: ModuleContract = serde_json::from_value(json!({
                "$schema": "urn:fortress:schema:v3:module-contract",
                "schema_version": 3,
                "id": "AF-SAMPLE-0001",
                "display_name": "Sample",
                "provides": [],
                "requires": [],
                "relationships": [],
                "constraints": [],
                "guarantees": [],
                "features": [],
                "behavior": [],
                "semantic_policy": {
                    "default": "UNDECLARED",
                    "capabilities": { "allow": capability_allow, "deny": capability_deny },
                    "effects": { "allow": effect_allow, "deny": effect_deny }
                }
        }))
        .unwrap();
        ModuleContract::from_json_str(&fixture.to_canonical_json().unwrap()).unwrap()
    }

    fn serialized(
        observation: &NativeFilesystemProjection<'_>,
        policy: Option<&ModuleSemanticPolicy>,
    ) -> Value {
        serde_json::to_value(project_native_filesystem_policy(observation, policy)).unwrap()
    }

    /// `T-NATIVE-EFFECT-PRECEDENCE-001`
    /// Fortress classification: infrastructure
    #[test]
    fn selects_original_effect_before_capability_in_both_directions() {
        with_observation(|observation| {
            for (original, kind, target, expected) in [
                (
                    contract(&[], &["filesystem"], &["filesystem.write"], &[]),
                    "EFFECT",
                    "filesystem.write",
                    "ALLOW",
                ),
                (
                    contract(&["filesystem"], &[], &[], &["filesystem.write"]),
                    "EFFECT",
                    "filesystem.write",
                    "DENY",
                ),
                (
                    contract(&[], &["filesystem"], &[], &[]),
                    "CAPABILITY",
                    "filesystem",
                    "DENY",
                ),
            ] {
                let observed = serialized(observation, original.semantic_policy());
                assert_eq!(observed["authored_policy"], "PRESENT");
                assert!(observed["effect_registry_sha256"].as_str().is_some());
                assert_eq!(observed["reachability"], "UNKNOWN");
                assert_eq!(
                    observed["sites"],
                    json!([{
                        "start_byte": 43,
                        "end_byte": 75,
                        "operation": "go_os_write_file",
                        "effects": [{
                            "effect": "filesystem.write",
                            "disposition": {
                                "status": "AUTHORED",
                                "decision": {
                                    "effect": "filesystem.write",
                                    "governing_target_kind": kind,
                                    "governing_target": target,
                                    "disposition": expected,
                                }
                            }
                        }]
                    }])
                );
                assert_eq!(
                    serialized(observation, original.semantic_policy()),
                    observed
                );
            }
        });
    }

    /// `T-NATIVE-EFFECT-LIMITS-001`
    /// Fortress classification: infrastructure
    #[test]
    fn separates_unlisted_policy_absent_policy_and_unmodeled_sites() {
        with_observation(|observation| {
            assert_eq!(observation.sites().len(), 4);
            assert!(matches!(
                observation.sites()[1].disposition(),
                NativeFilesystemDisposition::LocalOrShadowed
            ));
            assert!(matches!(
                observation.sites()[2].disposition(),
                NativeFilesystemDisposition::Unresolved
            ));
            assert!(matches!(
                observation.sites()[3].disposition(),
                NativeFilesystemDisposition::ContextUnavailable { .. }
            ));
            let policy = contract(&[], &[], &[], &["filesystem.read"]);
            let unlisted = serialized(observation, policy.semantic_policy());
            let absent = serialized(observation, None);
            assert_eq!(unlisted["sites"].as_array().unwrap().len(), 1);
            assert_eq!(absent["sites"].as_array().unwrap().len(), 1);
            assert_eq!(
                unlisted["sites"][0]["effects"][0]["disposition"]["status"],
                "UNDECLARED"
            );
            assert_eq!(
                absent["sites"][0]["effects"][0]["disposition"]["status"],
                "NO_AUTHORED_POLICY"
            );
            assert_eq!(absent["authored_policy"], "ABSENT");
            assert_eq!(absent["effect_registry_sha256"], Value::Null);
            assert_eq!(unlisted["reachability"], "UNKNOWN");
            assert_eq!(absent["reachability"], "UNKNOWN");
        });
    }

    /// `T-NATIVE-EFFECT-EMPTY-001`
    /// Fortress classification: infrastructure
    #[test]
    fn empty_modeled_inventory_keeps_denial_and_reachability_separate() {
        let batch = NativeFilesystemBatch {
            language: NativeFilesystemLanguage::Go,
            binding: BINDING,
            observation_sha256: BINDING_REF,
            calls: &[],
        };
        let observation = project_native_filesystem_effects(BINDING, SOURCE, &batch).unwrap();
        let original = contract(&[], &["filesystem"], &[], &[]);
        let result = serialized(&observation, original.semantic_policy());
        assert_eq!(result["sites"], json!([]));
        assert_eq!(result["authored_policy"], "PRESENT");
        assert_eq!(result["reachability"], "UNKNOWN");
    }
}
