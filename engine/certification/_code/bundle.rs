//! Pure compact bundle assembly from already-produced immutable evidence.

use crate::portable::{
    BundleManifest, PortableArtifact, PortableError, canonical, digest, failure, parse,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Portable unsigned bundle. Writing members is an explicit adapter operation.
#[derive(Clone, Debug)]
pub struct PortableBundle {
    /// Versioned inventory.
    pub manifest: BundleManifest,
    /// Checked relative member names and exact immutable bytes.
    pub members: BTreeMap<String, Vec<u8>>,
}

impl PortableBundle {
    /// Assembles portable evidence without invoking any semantic evaluator.
    /// Missing historical replay stays unavailable; producer assertions never
    /// authenticate their own evidence.
    /// # Errors
    /// Rejects invalid bindings, identities, versions, resources or predicate URIs.
    pub fn assemble(
        mut artifacts: BTreeMap<String, Vec<u8>>,
        generation_ref: Option<String>,
        predicate_type: &str,
    ) -> Result<Self, PortableError> {
        validate_predicate(predicate_type)?;
        let declaration = crate::declaration::ConformanceDeclaration::from_json_str(
            std::str::from_utf8(required(&artifacts, "conformance-declaration")?)
                .map_err(|e| failure("INVALID_JSON", e.to_string()))?,
        )
        .map_err(|e| failure("INVALID_DECLARATION", e.to_string()))?;
        let assessment = crate::assessment::ProfileAssessment::from_json_str(
            std::str::from_utf8(required(&artifacts, "profile-assessment")?)
                .map_err(|e| failure("INVALID_JSON", e.to_string()))?,
        )
        .map_err(|e| failure("INVALID_ASSESSMENT", e.to_string()))?;
        if declaration.binding != assessment.binding
            || declaration
                .digest()
                .map_err(|e| failure("INVALID_DECLARATION", e.to_string()))?
                != assessment.declaration_digest
        {
            return Err(failure(
                "BINDING_MISMATCH",
                "declaration and assessment differ",
            ));
        }
        let RequiredEvidence {
            mut unavailable,
            mut required_nodes,
            required_payloads,
        } = retain_replay(&mut artifacts, &declaration.binding.subject_ref)?;
        let application_only = artifacts
            .get("control-generation")
            .map(|b| parse(b))
            .transpose()?
            .is_some_and(|m| m["generation_kind"] == "APPLICATION")
            || artifacts
                .get("state-view")
                .map(|b| parse(b))
                .transpose()?
                .is_some_and(|v| v["$schema"] == "urn:fortress:derived:v3:state-view");
        let certification_availability = if artifacts.contains_key("certification") {
            "INCLUDED"
        } else if application_only {
            "NOT_APPLICABLE_APPLICATION"
        } else {
            "UNAVAILABLE"
        };
        if certification_availability == "UNAVAILABLE" {
            unavailable.push("certification".into());
        }
        for role in ["assessment-replay", "authority-assets"] {
            if !artifacts.contains_key(role) && !unavailable.iter().any(|s| s.starts_with(role)) {
                unavailable.push(role.into());
            }
        }
        required_nodes.sort();
        if required_nodes.windows(2).any(|p| p[0] == p[1]) {
            return Err(failure("DUPLICATE_IDENTITY", "duplicate graph node"));
        }
        unavailable.sort();
        let materialization_dependencies =
            omitted_products(&artifacts, &declaration.proof_manifest)?;
        let authority_assets = if artifacts.contains_key("authority-assets") {
            vec!["authority-assets".into()]
        } else {
            Vec::new()
        };
        let (descriptors, mut members) = describe(artifacts)?;
        let manifest = BundleManifest {
            schema: "urn:fortress:schema:v1:portable-bundle".into(), schema_version: 1,
            binding: declaration.binding.clone(), generation_ref,
            declaration_digest: declaration.digest().map_err(|e| failure("INVALID_DECLARATION", e.to_string()))?,
            assessment_digest: digest(&canonical(&serde_json::to_value(&assessment).map_err(|e| failure("INVALID_JSON", e.to_string()))?)?),
            profile_digest: assessment.profile_digest, artifacts: descriptors, required_nodes, required_payloads,
            authority_assets,
            certification_result_availability: certification_availability.into(),
            optional_projection_refs: declaration.proof_manifest, unavailable,
            materialization_dependencies,
            projection_losses: vec![
                "Unsigned producer assertions: integrity does not establish authenticity, semantic correctness or actual execution.".into(),
                "Omitted semantic projections require materialization to recompute analyzer conclusions; the offline verifier replays only the public evidence algebra.".into(),
                "Current repository freshness requires independently supplied exact source, context, authority and profile references.".into(),
            ],
        };
        let manifest_value =
            serde_json::to_value(&manifest).map_err(|e| failure("INVALID_JSON", e.to_string()))?;
        let manifest_bytes = canonical(&manifest_value)?;
        let statement = json!({"_type":"https://in-toto.io/Statement/v1", "subject":[{"name":"fortress-source", "digest":{"sha256":&manifest.binding.subject_ref[7..]}}],
            "predicateType":predicate_type, "predicate":{"schema_version":1,"manifest_digest":digest(&manifest_bytes),"binding":manifest.binding,"profile_digest":manifest.profile_digest,"authenticity":"UNVERIFIED"}});
        members.insert("manifest.json".into(), manifest_bytes);
        members.insert("statement.json".into(), canonical(&statement)?);
        Ok(Self { manifest, members })
    }
}

fn validate_predicate(predicate_type: &str) -> Result<(), PortableError> {
    let authority = predicate_type
        .strip_prefix("https://")
        .and_then(|s| s.split_once('/'))
        .map(|(host, _)| host);
    if !predicate_type.is_ascii()
        || predicate_type.len() > 2048
        || predicate_type.chars().any(char::is_whitespace)
        || authority.is_none_or(|s| s.is_empty() || s.contains('@'))
        || !predicate_type.ends_with("/v1")
    {
        return Err(failure(
            "INVALID_PREDICATE",
            "an explicit owner-controlled HTTPS v1 predicate URI is required",
        ));
    }
    Ok(())
}

fn omitted_products(
    artifacts: &BTreeMap<String, Vec<u8>>,
    proof: &[crate::declaration::DeclarationArtifact],
) -> Result<Vec<crate::declaration::DeclarationArtifact>, PortableError> {
    let mut omitted = proof
        .iter()
        .filter(|a| !artifacts.contains_key(&a.id))
        .map(|a| (a.id.clone(), a.clone()))
        .collect::<BTreeMap<_, _>>();
    if let Some(generation) = artifacts.get("control-generation") {
        let generation = parse(generation)?;
        for record in generation["artifacts"]
            .as_array()
            .ok_or_else(|| failure("INVALID_MANIFEST", "artifact inventory missing"))?
        {
            let id = record["id"]
                .as_str()
                .ok_or_else(|| failure("INVALID_MANIFEST", "artifact identity missing"))?;
            if artifacts.contains_key(id) {
                continue;
            }
            let item = crate::declaration::DeclarationArtifact {
                id: id.into(),
                content_digest: record["content_digest"]
                    .as_str()
                    .ok_or_else(|| failure("INVALID_MANIFEST", "artifact digest missing"))?
                    .into(),
                byte_count: record["byte_count"]
                    .as_u64()
                    .ok_or_else(|| failure("INVALID_MANIFEST", "artifact size missing"))?,
            };
            if omitted.get(id).is_some_and(|old| old != &item) {
                return Err(failure(
                    "BINDING_MISMATCH",
                    "omitted product identities conflict",
                ));
            }
            omitted.insert(id.into(), item);
        }
    }
    Ok(omitted.into_values().collect())
}

fn required<'a>(
    artifacts: &'a BTreeMap<String, Vec<u8>>,
    role: &str,
) -> Result<&'a [u8], PortableError> {
    artifacts
        .get(role)
        .map(Vec::as_slice)
        .ok_or_else(|| failure("MISSING_ARTIFACT", role))
}

type Described = (Vec<PortableArtifact>, BTreeMap<String, Vec<u8>>);
fn describe(artifacts: BTreeMap<String, Vec<u8>>) -> Result<Described, PortableError> {
    if artifacts.len() > 128 {
        return Err(failure("RESOURCE_LIMIT", "artifact count exceeds 128"));
    }
    let mut members = BTreeMap::new();
    let mut descriptors = Vec::new();
    let mut total = 0usize;
    let mut roles = BTreeSet::new();
    for (id, bytes) in artifacts {
        if bytes.is_empty() || bytes.len() > 32 * 1024 * 1024 {
            return Err(failure("RESOURCE_LIMIT", "artifact size outside admission"));
        }
        total = total
            .checked_add(bytes.len())
            .filter(|n| *n <= 128 * 1024 * 1024)
            .ok_or_else(|| failure("RESOURCE_LIMIT", "bundle exceeds 128 MiB"))?;
        if !roles.insert(id.clone()) {
            return Err(failure("DUPLICATE_IDENTITY", id));
        }
        let binary = id.starts_with("provider-payload:");
        let value: Option<Value> = if binary { None } else { Some(parse(&bytes)?) };
        let wire_digest = digest(&bytes);
        let member = format!(
            "artifacts/{}.{}",
            &wire_digest[7..],
            if binary { "bin" } else { "json" }
        );
        descriptors.push(PortableArtifact {
            id,
            member: member.clone(),
            wire_digest,
            jcs_digest: value
                .as_ref()
                .map(|v| canonical(v).map(|b| digest(&b)))
                .transpose()?,
            byte_count: bytes.len(),
            media_type: if binary {
                "application/octet-stream"
            } else {
                "application/json"
            }
            .into(),
            schema: value
                .as_ref()
                .and_then(|v| v["$schema"].as_str())
                .unwrap_or(if binary {
                    "urn:fortress:portable:v1:raw-provider-payload"
                } else {
                    "urn:fortress:portable:v1:retained-input"
                })
                .into(),
            required: true,
        });
        if members.insert(member, bytes).is_some() {
            return Err(failure(
                "DUPLICATE_IDENTITY",
                "multiple roles name one member",
            ));
        }
    }
    Ok((descriptors, members))
}

struct RequiredEvidence {
    unavailable: Vec<String>,
    required_nodes: Vec<String>,
    required_payloads: BTreeMap<String, String>,
}

fn retain_replay(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    subject_ref: &str,
) -> Result<RequiredEvidence, PortableError> {
    let mut unavailable: Vec<String> = Vec::new();
    let mut required_nodes = Vec::new();
    let mut required_payloads = BTreeMap::new();
    if let Some(bytes) = artifacts.get("evidence-graph") {
        let graph = parse(bytes)?;
        let validated: crate::certification::EvidenceGraph = serde_json::from_value(graph.clone())
            .map_err(|e| failure("INVALID_GRAPH", e.to_string()))?;
        validated
            .validate()
            .map_err(|e| failure("INVALID_GRAPH", e.to_string()))?;
        if validated.subject() != subject_ref {
            return Err(failure(
                "BINDING_MISMATCH",
                "graph subject differs from declaration",
            ));
        }
        let nodes = graph["nodes"]
            .as_array()
            .ok_or_else(|| failure("INVALID_GRAPH", "nodes missing"))?;
        for node in nodes {
            required_nodes.push(
                node["id"]
                    .as_str()
                    .ok_or_else(|| failure("INVALID_GRAPH", "node identity missing"))?
                    .to_owned(),
            );
        }
        let replays = nodes
            .iter()
            .filter(|n| n["kind"] == "assessment_replay")
            .collect::<Vec<_>>();
        match replays.as_slice() {
            [node] => {
                artifacts.insert("assessment-replay".into(), canonical(&node["payload"]["replay"])?);
                artifacts.insert("authority-assets".into(), canonical(&node["payload"]["authority"])?);
                artifacts.insert("audit".into(), canonical(&node["payload"]["audit"])?);
                for leaf in node["payload"]["replay"]["evidence"].as_array()
                    .ok_or_else(|| failure("INVALID_REPLAY", "evidence array missing"))? {
                    let id = leaf["id"].as_str().ok_or_else(|| failure("INVALID_REPLAY", "leaf identity missing"))?;
                    let payload = leaf["payload_digest"].as_str().ok_or_else(|| failure("INVALID_REPLAY", "leaf payload identity missing"))?;
                    if required_payloads.insert(id.into(), payload.into()).is_some() {
                        return Err(failure("DUPLICATE_IDENTITY", "duplicate replay leaf"));
                    }
                    if leaf["proposition"] == "UNAVAILABLE" { unavailable.push(format!("required evidence unavailable for {id}")); }
                }
            }
            [] => unavailable.push("assessment-replay: original obligation/admission inputs were not retained by this historical producer".into()),
            _ => return Err(failure("DUPLICATE_IDENTITY", "multiple assessment replay observations")),
        }
    } else {
        unavailable.push("evidence-graph".into());
    }
    Ok(RequiredEvidence {
        unavailable,
        required_nodes,
        required_payloads,
    })
}
