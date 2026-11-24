//! Shared physical source capture for explicit native language observations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::architecture_realization::{ReconciliationRecord, compare_scoped_dependencies};
use crate::audit::{
    NativeAuthorityScope, NativeObservationBinding, bind_native_observation_source,
    observe_candidate_source,
};
use crate::heavy_admission::{DirectoryIdentity, assert_no_incomplete_migration};
use crate::implementation_observation::{
    Conditionality, ImplementationObservation, ImplementationObservationInput,
    ObservationProvenance, ObservedImplementation, SnapshotBoundFile, SourceLocation,
    SourceOwnership, SourceOwnershipAuthority, SourceOwnershipBasis, SourceOwnershipDiagnostic,
};
use crate::observation::SourceView;
use crate::program_semantics::native_body::{NativeBoundCall, NativeCallTopology};

const MAX_DEPENDENCY_FILES: usize = 8192;
const MAX_DEPENDENCY_BYTES: usize = 32 << 20;

pub(crate) struct NativeSource<'a> {
    root: &'a Path,
    directory: DirectoryIdentity,
    pub(crate) view: SourceView,
    pub(crate) binding: NativeObservationBinding,
}

pub(crate) enum NativeSourceError {
    Unavailable(String),
    Changed,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ScopedDependencyIntent {
    Compared {
        ccg_digest: String,
        records: Vec<ReconciliationRecord>,
    },
    OriginalIntentUnavailable,
    NativeObservationUnavailable,
}

impl<'a> NativeSource<'a> {
    pub(crate) fn capture(root: &'a Path, language: &str) -> Result<Self, NativeSourceError> {
        Self::capture_with(root, language, NativeAuthorityScope::Observation)
    }

    pub(crate) fn capture_for_dependencies(
        root: &'a Path,
        language: &str,
    ) -> Result<Self, NativeSourceError> {
        Self::capture_with(root, language, NativeAuthorityScope::Dependencies)
    }

    pub(crate) fn capture_with(
        root: &'a Path,
        language: &str,
        scope: NativeAuthorityScope<'_>,
    ) -> Result<Self, NativeSourceError> {
        let directory = DirectoryIdentity::capture(root).map_err(unavailable)?;
        let view = observe_source(root)?;
        let binding =
            bind_native_observation_source(&view, language, scope).map_err(unavailable)?;
        if !directory.matches(root).map_err(unavailable)? {
            return Err(NativeSourceError::Changed);
        }
        Ok(Self {
            root,
            directory,
            view,
            binding,
        })
    }

    pub(crate) fn dependency_input<'path>(
        &self,
        paths: impl IntoIterator<Item = &'path str>,
    ) -> Result<(ImplementationObservationInput, &[SourceOwnershipDiagnostic]), NativeSourceError>
    {
        let ownership = self
            .binding
            .dependency_ownership
            .as_ref()
            .ok_or_else(|| unavailable("Native dependency ownership was not selected"))?;
        let paths = paths.into_iter().collect::<BTreeSet<_>>();
        if paths.len() > MAX_DEPENDENCY_FILES {
            return Err(unavailable(
                "Native dependency input exceeds its file limit",
            ));
        }
        let mut size = 0usize;
        let mut files = Vec::with_capacity(paths.len());
        for &path in &paths {
            let bytes = self
                .view
                .bytes(path)
                .ok_or_else(|| unavailable("Native dependency source was not observed"))?;
            size = size.saturating_add(bytes.len());
            if size > MAX_DEPENDENCY_BYTES {
                return Err(unavailable(
                    "Native dependency input exceeds its byte limit",
                ));
            }
            files.push(SnapshotBoundFile::from_bytes(path, bytes));
        }
        let input = ImplementationObservationInput::new_with_ownership(
            &self.binding.source_fingerprint,
            files,
            ownership
                .ownerships()
                .iter()
                .filter(|owner| paths.contains(owner.source_path()))
                .cloned()
                .collect(),
        );
        Ok((input, ownership.diagnostics()))
    }

    pub(crate) fn compare_dependency_intent(
        &self,
        observed: Option<&ObservedImplementation>,
    ) -> Result<ScopedDependencyIntent, serde_json::Error> {
        let Some(graph) = &self.binding.dependency_intent else {
            return Ok(ScopedDependencyIntent::OriginalIntentUnavailable);
        };
        let Some(observed) = observed else {
            return Ok(ScopedDependencyIntent::NativeObservationUnavailable);
        };
        Ok(ScopedDependencyIntent::Compared {
            ccg_digest: graph.digest()?,
            records: compare_scoped_dependencies(graph, observed),
        })
    }

    pub(crate) fn original_declared_owner(
        &self,
        path: &str,
    ) -> Result<Option<SourceOwnership>, NativeSourceError> {
        let (input, diagnostics) = self.dependency_input([path])?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.source_path() == path)
        {
            return Ok(None);
        }
        let [owner] = input.ownerships() else {
            return Ok(None);
        };
        Ok(
            (owner.authority() == SourceOwnershipAuthority::DeclaredModule
                && owner.basis() == SourceOwnershipBasis::LogicalPathBinding)
                .then(|| owner.clone()),
        )
    }

    pub(crate) fn revalidate(&self) -> Result<(), NativeSourceError> {
        if observe_source(self.root)? != self.view
            || !self.directory.matches(self.root).map_err(unavailable)?
        {
            return Err(NativeSourceError::Changed);
        }
        Ok(())
    }
}

fn observe_source(root: &Path) -> Result<SourceView, NativeSourceError> {
    assert_no_incomplete_migration(root).map_err(unavailable)?;
    let view = observe_candidate_source(root).map_err(unavailable)?;
    assert_no_incomplete_migration(root).map_err(unavailable)?;
    Ok(view)
}

fn unavailable(error: impl std::fmt::Display) -> NativeSourceError {
    NativeSourceError::Unavailable(error.to_string())
}

pub(crate) fn project_native_call_sensitivity(
    language: &str,
    observation: &serde_json::Value,
    result: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "$schema": "urn:fortress:derived:v1:native-call-return-sensitivity",
        "schema_version": 1,
        "scope": "BOUNDED_BOOLEAN_CALL_RETURN_SENSITIVITY",
        "language": language,
        "target_execution": "NOT_RUN",
        "canonical_finding_or_certificate": "NOT_ISSUED",
        "observation": observation,
        "sensitivity": result,
    })
}

pub(crate) fn project_native_call_topology(
    language: &str,
    observation: &serde_json::Value,
    graph: &NativeCallTopology<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "$schema": "urn:fortress:derived:v1:native-call-topology-inspection",
        "schema_version": 1,
        "scope": "SOURCE_BOUND_STATIC_CALL_CLOSURE",
        "language": language,
        "runtime_execution": "NOT_RUN",
        "observation": observation,
        "graph": graph,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum NativeCallOwnershipState {
    SameModule,
    CrossModule,
    DeclaredOwnerUnavailable,
}

#[derive(Serialize)]
struct NativeCallOwnership<'a> {
    call_site: &'a str,
    caller: Option<&'a SourceOwnership>,
    callee: Option<&'a SourceOwnership>,
    relationship: NativeCallOwnershipState,
}

pub(crate) fn project_native_call_ownership(
    source: &NativeSource<'_>,
    language: &str,
    observation: &serde_json::Value,
    topology: &NativeCallTopology<'_>,
) -> Result<serde_json::Value, NativeSourceError> {
    let sites = match topology {
        NativeCallTopology::Available { sites, .. } => Some(sites.as_slice()),
        NativeCallTopology::Unavailable { .. } => None,
    };
    let paths = sites
        .into_iter()
        .flatten()
        .flat_map(|site| {
            let call = site.call();
            [call.span.path.as_str(), call.target.span.path.as_str()]
        })
        .collect::<BTreeSet<_>>();
    let (input, diagnostics) = source.dependency_input(paths)?;
    let disputed_paths = diagnostics
        .iter()
        .map(SourceOwnershipDiagnostic::source_path)
        .collect::<BTreeSet<_>>();
    let mut owners = BTreeMap::new();
    for owner in input.ownerships() {
        let path = owner.source_path();
        let declared = owner.authority() == SourceOwnershipAuthority::DeclaredModule
            && owner.basis() == SourceOwnershipBasis::LogicalPathBinding
            && !disputed_paths.contains(path);
        owners
            .entry(path)
            .and_modify(|value| *value = None)
            .or_insert_with(|| declared.then_some(owner));
    }
    let mut relationships = Vec::new();
    let mut facts = Vec::new();
    for site in sites.into_iter().flatten() {
        let call = site.call();
        let origin_owner = owners.get(call.span.path.as_str()).copied().flatten();
        let target_owner = owners
            .get(call.target.span.path.as_str())
            .copied()
            .flatten();
        let relationship = match (origin_owner, target_owner) {
            (Some(origin), Some(target)) if origin.owner() == target.owner() => {
                NativeCallOwnershipState::SameModule
            }
            (Some(origin), Some(target)) => {
                facts.push(native_call_dependency(language, origin, target, call)?);
                NativeCallOwnershipState::CrossModule
            }
            _ => NativeCallOwnershipState::DeclaredOwnerUnavailable,
        };
        relationships.push(NativeCallOwnership {
            call_site: &call.reference,
            caller: origin_owner,
            callee: target_owner,
            relationship,
        });
    }
    let observed = sites.map(|_| {
        ObservedImplementation::from_facts(
            &source.binding.source_fingerprint,
            "fortress-native-call-dependency",
            "1.0.0",
            facts,
            Vec::new(),
        )
    });
    let original_intent = source
        .compare_dependency_intent(observed.as_ref())
        .map_err(unavailable)?;
    Ok(serde_json::json!({
        "$schema": "urn:fortress:derived:v1:native-call-module-boundaries",
        "schema_version": 1,
        "scope": "POSITIVE_STATIC_CALLS_UNDER_ORIGINAL_LOGICAL_OWNERSHIP",
        "language": language,
        "target_execution": "NOT_RUN",
        "canonical_finding_or_certificate": "NOT_ISSUED",
        "source_view_sha256": source.view.digest(),
        "source_manifest_sha256": source.binding.source_manifest_digest,
        "authority_sha256": source.binding.authority_digest,
        "observation": observation,
        "topology": topology,
        "ownership_sites": relationships,
        "original_intent": original_intent,
    }))
}

fn native_call_dependency(
    language: &str,
    origin: &SourceOwnership,
    target: &SourceOwnership,
    call: &NativeBoundCall,
) -> Result<ImplementationObservation, NativeSourceError> {
    let location = SourceLocation::new(
        u32::try_from(call.span.start_line).map_err(unavailable)?,
        u32::try_from(call.span.start_byte_column).map_err(unavailable)?,
    );
    Ok(ImplementationObservation::governed(
        origin.owner(),
        origin.source_path(),
        target.owner(),
        Conditionality::Unestablished,
        ObservationProvenance::new(
            origin.source_path(),
            origin.owner(),
            call.target.name.as_str(),
            location,
            Some(target.source_path().into()),
        ),
    )
    .with_language(language))
}
