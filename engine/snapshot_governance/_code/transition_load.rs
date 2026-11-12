//! Explicit endpoint capture and registered CONTROL history loading, never comparison semantics.
use crate::contract_coherency::ContractCoherencyGraph;
use crate::control_layout::ControlLayout;
use crate::control_manifest::{ArtifactStorage, AssessmentGenerationManifest};
use crate::observation::SourceView;
use crate::semantic_conformance::PolicyDisposition as D;
use crate::state_governance::{
    Axis, AxisInput, ComparisonContext, ComparisonState, Entity, FinitePolicy,
    MAX_TRANSITION_BYTES, Promise, StateAssets, TransitionError,
};
use crate::state_view::StateView;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn error(code: &str, message: impl Into<String>) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
fn hash<T: serde::Serialize>(v: &T) -> Result<String, TransitionError> {
    crate::declaration::canonical(v)
        .map(|b| format!("sha256:{:x}", Sha256::digest(b)))
        .map_err(|e| error("INVALID_INPUT", e.to_string()))
}
fn raw(b: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(b))
}
/// Loads an explicit current, historical generation or comparison-input file.
/// Current evaluation is explicit and read-only; no historical evaluator executes.
/// # Errors
/// Returns typed input, integrity or resource errors; missing generations remain unavailable.
pub fn load_comparison_state(
    root: &Path,
    reference: &str,
) -> Result<ComparisonState, TransitionError> {
    if reference == "current" {
        let view = crate::audit::compile_comparison_view(root)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        let assets = crate::audit::prepare_comparison_assets(root, &view)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        let state=ComparisonState{schema:"urn:fortress:derived:v2:comparison-state".into(),schema_version:2,source_ref:Some(view.source_ref.clone()),view:Some(view),retained_application:None,assets:Some(assets),origin_ref:None,limitations:vec!["Explicit current capture evaluates existing installed owners without executing project build scripts or historical code.".into()]};
        state.validate()?;
        return Ok(state);
    }
    if let Some(generation) = reference.strip_prefix("generation:") {
        return load_generation(root, generation);
    }
    let path = Path::new(reference);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let anchor = absolute
        .ancestors()
        .last()
        .ok_or_else(|| error("INVALID_INPUT", "comparison file has no absolute root"))?;
    let bytes = crate::query::safe_read(anchor, &absolute, MAX_TRANSITION_BYTES as u64)
        .map_err(|e| error(&e.code, e.message))?;
    let text = std::str::from_utf8(&bytes).map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    let shape: Value =
        crate::wire::parse_public_json(text).map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    if matches!(
        shape["$schema"].as_str(),
        Some(
            "urn:fortress:derived:v1:comparison-state" | "urn:fortress:derived:v2:comparison-state"
        )
    ) {
        return ComparisonState::from_json_str(text);
    }
    let view = StateView::from_json_str(text).map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    let mut state = ComparisonState::unavailable(Some(raw(&bytes)));
    state.source_ref = Some(view.source_ref.clone());
    state.view = Some(view);
    state.limitations=vec!["Original StateView supplied without necessary source/authority assets; affected comparisons remain NOT_COMPARABLE.".into()];
    state.validate()?;
    Ok(state)
}
fn load_generation(root: &Path, generation: &str) -> Result<ComparisonState, TransitionError> {
    let layout = ControlLayout::standard();
    let path = layout
        .generation_path(generation, None)
        .ok_or_else(|| error("INVALID_INPUT", "invalid registered generation reference"))?;
    let bytes = match crate::query::safe_read(root, &root.join(path), MAX_TRANSITION_BYTES as u64) {
        Ok(b) => b,
        Err(e) if e.code == "MISSING" => {
            return Ok(ComparisonState::unavailable(Some(generation.into())));
        }
        Err(e) => return Err(error(&e.code, e.message)),
    };
    let manifest = AssessmentGenerationManifest::from_json_str(
        std::str::from_utf8(&bytes).map_err(|e| error("INVALID_INPUT", e.to_string()))?,
    )
    .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
    if manifest
        .generation_digest()
        .map_err(|e| error("INVALID_INPUT", e.to_string()))?
        != generation
    {
        return Err(error(
            "INTEGRITY_ERROR",
            "historical manifest digest differs",
        ));
    }
    // Existing generations retain declaration/assessment pairs, not complete StateViews.
    // Verify included bytes and preserve their original meaning without fabricating metadata.
    if manifest.artifacts().len() > 256 {
        return Err(error(
            "RESOURCE_LIMIT",
            "historical artifact inventory exceeds admission",
        ));
    }
    let mut pair = BTreeMap::new();
    let mut loaded = 0usize;
    let mut missing = Vec::new();
    for artifact in manifest.artifacts() {
        if let ArtifactStorage::Included { member_name } = artifact.storage() {
            let path = layout
                .generation_path(generation, Some(artifact.id()))
                .ok_or_else(|| error("INVALID_INPUT", "unregistered historical member"))?;
            if Path::new(&path).file_name().and_then(|p| p.to_str()) != Some(member_name) {
                return Err(error(
                    "INTEGRITY_ERROR",
                    "historical member differs from registered role",
                ));
            }
            let bytes = match crate::query::safe_read(
                root,
                &root.join(path),
                MAX_TRANSITION_BYTES as u64,
            ) {
                Ok(bytes) => bytes,
                Err(e) if e.code == "MISSING" => {
                    missing.push(format!("Missing historical artifact {}", artifact.id()));
                    continue;
                }
                Err(e) => return Err(error(&e.code, e.message)),
            };
            loaded = loaded
                .checked_add(bytes.len())
                .filter(|n| *n <= 128 * 1024 * 1024)
                .ok_or_else(|| {
                    error(
                        "RESOURCE_LIMIT",
                        "historical evidence exceeds aggregate admission",
                    )
                })?;
            if raw(&bytes) != artifact.content_digest()
                || bytes.len() as u64 != artifact.byte_count()
            {
                return Err(error("INTEGRITY_ERROR", "historical artifact bytes differ"));
            }
            if ["conformance-declaration", "profile-assessment"].contains(&artifact.id()) {
                pair.insert(artifact.id().to_owned(), bytes);
            }
        }
    }
    let mut state = ComparisonState::unavailable(Some(generation.into()));
    retain_pair(&mut state, &pair, manifest.project())?;
    state.limitations.extend(missing);
    state.limitations.push("Intact historical generation has no complete retained StateView/source/authority asset set. Its historical certificate remains historical, never reconstructed as current evidence. Supply a captured comparison-state file for complete comparison.".into());
    state.validate()?;
    Ok(state)
}

pub(crate) fn assets_from_source(
    files: &SourceView,
    view: &StateView,
    ccg: Option<&ContractCoherencyGraph>,
    standard: Option<&crate::standard::StandardBundle>,
    ownerships: &[crate::implementation_observation::SourceOwnership],
) -> Result<StateAssets, TransitionError> {
    let mut assets = StateAssets {
        subject_ref: view.source_ref.clone(),
        complete_axes: if ccg.is_some() && view.application.is_some() {
            BTreeSet::from([
                Axis::Subject,
                Axis::Intent,
                Axis::Authority,
                Axis::Governance,
            ])
        } else {
            BTreeSet::from([Axis::Subject])
        },
        inputs: vec![],
        entities: vec![],
        policies: vec![],
        standard_ref: standard.map(|s| s.digest().to_owned()),
        profile_refs: BTreeSet::new(),
        evaluator_ref: None,
        exclusions_ref: None,
        exclusions: None,
        reference_facts: None,
    };
    let owners = ownerships
        .iter()
        .filter(|o| {
            o.authority()
                == crate::implementation_observation::SourceOwnershipAuthority::DeclaredModule
        })
        .map(|o| (o.source_path(), o.owner()))
        .collect::<BTreeMap<_, _>>();
    for (path, bytes) in files {
        let mut input = input_record(path, bytes)?;
        if let Some(owner) = owners.get(path.as_str()) {
            input.scope_refs.insert((*owner).to_owned());
        }
        assets.inputs.push(input);
    }
    if let Some(app) = &view.application {
        assets.profile_refs = app
            .declaration
            .required_dimension_manifest
            .profiles
            .iter()
            .map(hash)
            .collect::<Result<_, _>>()?;
        assets.evaluator_ref = Some(hash(
            &json!({"producer":app.declaration.producer,"semantic":crate::semantic_conformance::SEMANTIC_CONFORMANCE_VERSION,"state_effect":crate::state_effect_analysis::STATE_EFFECT_ANALYSIS_VERSION}),
        )?);
    }
    let layout = ControlLayout::standard();
    if let Some(path) = layout.role_path(crate::control_layout::ControlRole::ProjectConfiguration)
        && let Some(bytes) = files.get(path)
    {
        let value: Value = crate::wire::parse_public_json(
            std::str::from_utf8(bytes).map_err(|e| error("INVALID_INPUT", e.to_string()))?,
        )
        .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        let selectors = value["observation_exclusions"]
            .as_array()
            .ok_or_else(|| error("INVALID_INPUT", "exclusion inventory is malformed"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| error("INVALID_INPUT", "exclusion selector is not text"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        assets.exclusions_ref = Some(hash(&selectors)?);
        assets.exclusions = Some(selectors);
    }
    if let Some(ccg) = ccg {
        for (id, module) in ccg.modules() {
            add_entities(&mut assets, id, module.contract_path(), module.contract())?;
            if let Some(policy) = module.contract().semantic_policy() {
                add_policy(&mut assets, id, module.contract_path(), policy, view)?;
            }
        }
        let references = crate::reference_resolution::evaluate_reference_resolution(
            ccg,
            files,
            standard.map_or("unknown", |s| s.edition()),
        )
        .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        assets.reference_facts = Some(
            references
                .index()
                .semantic_reference_identities()
                .iter()
                .map(hash)
                .collect::<Result<_, _>>()?,
        );
    }
    Ok(assets)
}
fn input_record(path: &str, bytes: &[u8]) -> Result<AxisInput, TransitionError> {
    use crate::affected_analysis::AuthorityInputKind as K;
    let kind = crate::affected_analysis::classify_authority_path(path);
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| crate::wire::parse_public_json::<Value>(s).ok());
    let identity = parsed
        .as_ref()
        .and_then(|v| v["id"].as_str())
        .filter(|_| kind == K::ModuleContract)
        .map_or_else(|| path.to_owned(), |id| format!("module-contract:{id}"));
    let semantic = parsed
        .as_ref()
        .map(hash)
        .transpose()?
        .unwrap_or_else(|| raw(bytes));
    let axes: &[Axis] = match kind {
        K::ModuleContract
        | K::FunctionContract
        | K::StateContract
        | K::InformationFlowPolicy
        | K::EnvironmentContract
        | K::BehavioralRealizationContract => &[Axis::Intent],
        K::FindingGovernance => &[Axis::Governance],
        K::StandardAuthority | K::EffectSummary => &[Axis::Authority],
        K::ProjectConfiguration => &[Axis::Intent, Axis::Authority],
        K::CargoAuthority => &[Axis::Subject, Axis::Authority],
        _ => &[Axis::Subject],
    };
    let mut roles = axes
        .iter()
        .map(|a| (*a, semantic.clone()))
        .collect::<BTreeMap<_, _>>();
    if kind == K::ModuleContract
        && let Some(mut value) = parsed
        && let Some(object) = value.as_object_mut()
    {
        let ecosystem = object.remove("ecosystem");
        roles.insert(Axis::Intent, hash(&value)?);
        if let Some(e) = ecosystem {
            roles.insert(Axis::Authority, hash(&e)?);
        }
    }
    Ok(AxisInput {
        scope_refs: BTreeSet::new(),
        id: identity,
        path: path.into(),
        content_ref: raw(bytes),
        roles,
    })
}
fn add_entities(
    a: &mut StateAssets,
    id: &str,
    path: &str,
    c: &crate::contract_coherency::ModuleContract,
) -> Result<(), TransitionError> {
    a.entities.push(Entity {
        id: id.into(),
        kind: "module".into(),
        semantic_ref: hash(c)?,
        path: Some(path.into()),
        promise: None,
    });
    let mut clauses = BTreeMap::new();
    for f in c.features() {
        for r in f.requirements() {
            let value =
                serde_json::to_value(r).map_err(|e| error("INVALID_INPUT", e.to_string()))?;
            let rid = value["id"]
                .as_str()
                .ok_or_else(|| error("INVALID_INPUT", "requirement identity missing"))?;
            let d = hash(r)?;
            clauses.insert(rid.to_owned(), d.clone());
            a.entities.push(Entity {
                id: rid.into(),
                kind: "requirement".into(),
                semantic_ref: d,
                path: Some(path.into()),
                promise: None,
            });
        }
    }
    for g in c.guarantees() {
        let required = g
            .requirements()
            .iter()
            .map(|id| {
                clauses
                    .get(id)
                    .cloned()
                    .map(|d| (id.clone(), d))
                    .ok_or_else(|| error("INVALID_INPUT", "guarantee requirement missing"))
            })
            .collect::<Result<_, _>>()?;
        a.entities.push(Entity {
            id: g.id().into(),
            kind: "guarantee".into(),
            semantic_ref: hash(&json!([g, required]))?,
            path: Some(path.into()),
            promise: Some(Promise {
                subject: hash(g.subject())?,
                quantifier: "ALL".into(),
                clauses: required,
            }),
        });
    }
    Ok(())
}
fn add_policy(
    a: &mut StateAssets,
    id: &str,
    path: &str,
    policy: &crate::contract_coherency::ModuleSemanticPolicy,
    view: &StateView,
) -> Result<(), TransitionError> {
    let compiled = crate::semantic_conformance::compile_effective_policy(
        policy,
        &crate::state_effect_analysis::registered_effect_catalog(),
    );
    let Some(app) = &view.application else {
        return Ok(());
    };
    let detail = app
        .declaration
        .claims
        .iter()
        .filter_map(|c| c.semantic_claim.as_ref())
        .find(|d| d.module_id == id);
    let scope = detail.map_or("all-module-owned-executable", |d| d.scope_selector.as_str());
    let context = detail.map_or(app.declaration.binding.context_ref.as_str(), |d| {
        d.context_digest.as_str()
    });
    let origin = a
        .inputs
        .iter()
        .find(|i| i.path == path)
        .ok_or_else(|| error("INVALID_INPUT", "policy origin missing"))?;
    let select = |want| {
        compiled
            .decisions()
            .iter()
            .filter(|d| d.disposition() == Some(want))
            .map(|d| d.effect().to_owned())
            .collect()
    };
    let universe = compiled
        .decisions()
        .iter()
        .map(|d| d.effect().to_owned())
        .collect::<BTreeSet<_>>();
    let complete = compiled.entries().iter().all(|entry| {
        !entry.mapped_effects().is_empty()
            && entry
                .mapped_effects()
                .iter()
                .all(|effect| universe.contains(effect))
    });
    a.policies.push(FinitePolicy {
        id: id.into(),
        origin_ref: origin.content_ref.clone(),
        origin_kind: "AUTHORED".into(),
        vocabulary_ref: compiled.registry_digest().into(),
        scope: scope.into(),
        quantifier: "ALL".into(),
        context_ref: context.into(),
        complete,
        universe: compiled
            .decisions()
            .iter()
            .map(|d| d.effect().into())
            .collect(),
        denied: select(D::Deny),
        allowed: select(D::Allow),
    });
    Ok(())
}

/// Reads an explicit bounded counterfactual/citation context without executing code.
/// # Errors
/// Refuses links, unsafe paths, malformed JSON and resource exhaustion.
pub fn load_comparison_context(path: &Path) -> Result<ComparisonContext, TransitionError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?
            .join(path)
    };
    let anchor = absolute
        .ancestors()
        .last()
        .ok_or_else(|| error("INVALID_INPUT", "context has no absolute root"))?;
    let bytes = crate::query::safe_read(anchor, &absolute, MAX_TRANSITION_BYTES as u64)
        .map_err(|e| error(&e.code, e.message))?;
    crate::wire::parse_public_json(
        std::str::from_utf8(&bytes).map_err(|e| error("INVALID_INPUT", e.to_string()))?,
    )
    .map_err(|e| error("INVALID_INPUT", e.to_string()))
}

fn retain_pair(
    state: &mut ComparisonState,
    pair: &BTreeMap<String, Vec<u8>>,
    project: &str,
) -> Result<(), TransitionError> {
    if let (Some(d), Some(a)) = (
        pair.get("conformance-declaration"),
        pair.get("profile-assessment"),
    ) {
        let text = |b: &Vec<u8>| {
            std::str::from_utf8(b)
                .map(str::to_owned)
                .map_err(|e| error("INVALID_INPUT", e.to_string()))
        };
        let declaration = crate::declaration::ConformanceDeclaration::from_json_str(&text(d)?)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        let assessment = crate::assessment::ProfileAssessment::from_json_str(&text(a)?)
            .map_err(|e| error("INVALID_INPUT", e.to_string()))?;
        state.source_ref = Some(declaration.binding.subject_ref.clone());
        state.retained_application = Some(crate::application::ApplicationAssessment {
            portable_replay: None,
            project: project.into(),
            declaration,
            assessment,
            evidence: vec![],
            obligations: vec![],
            evidence_inputs: None,
            provider_requirements: vec![],
        });
    }

    Ok(())
}
