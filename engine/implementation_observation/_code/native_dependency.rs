//! Source ownership projection of already admitted native dependency observations.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use serde::Serialize;

use super::{
    Conditionality, ImplementationObservation, ImplementationObservationInput, ObservationIssue,
    ObservationIssueKind, ObservationProvenance, ObservedImplementation, ResolutionStatus,
    SourceLocation, SourceOwnershipAuthority, TargetClassification,
};

const MAX_SITES: usize = 4096;
const MAX_PACKAGE_FILES: usize = 64;
const MAX_ENDPOINTS: usize = 8192;
const MAX_ENDPOINT_BYTES: usize = 32 << 20;
const MAX_PATH_BYTES: usize = 1024;
const MAX_REFERENCE_BYTES: usize = 1024;
const VERSION: &str = "1.0.0";

/// Language and scope of an already admitted native source observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDependencyLanguage {
    /// Import in a fully admitted closed Go package graph.
    Go,
    /// File candidate in an admitted scoped Python static import lookup.
    Python,
}

impl NativeDependencyLanguage {
    fn name(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "python",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "py",
        }
    }

    fn analyzer(self) -> &'static str {
        match self {
            Self::Go => "fortress-go-source-dependency-adapter",
            Self::Python => "fortress-python-source-dependency-adapter",
        }
    }
}

/// Source and authority selected independently by the exact evaluation owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeDependencyContext<'a> {
    /// Complete stabilized snapshot identity.
    pub snapshot_fingerprint: &'a str,
    /// Exact immutable source view identity.
    pub source_view_sha256: &'a str,
    /// Original governing authority identity.
    pub authority_sha256: &'a str,
    /// Exact language observation and evaluation context.
    pub context_sha256: &'a str,
}

/// One physical source artifact from the admitted producer's exact inventory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeDependencyFile<'a> {
    /// Exact repository-relative path.
    pub path: &'a str,
    /// Digest of the complete admitted file.
    pub sha256: &'a str,
}

/// One exact location of an admitted import or reference in retained source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeDependencyOccurrence<'a> {
    /// Physical source artifact containing the reference.
    pub file: NativeDependencyFile<'a>,
    /// Inclusive UTF-8 byte offset in the exact file.
    pub start_byte: usize,
    /// Exclusive UTF-8 byte offset in the exact file.
    pub end_byte: usize,
    /// Exact scoped spelling supplied by the admitted producer.
    pub reference: &'a str,
}

/// A scoped reason for retaining a reference without a supported target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeDependencyUnresolved {
    /// No admitted source target was available in the relevant scope.
    MissingFromAdmittedScope,
    /// The target or lookup context was outside supported semantics.
    UnsupportedContext,
    /// The producer had incompatible candidate origins.
    AmbiguousSourceOrigin,
    /// The admitted directories establish a namespace but no exact file origin.
    NamespaceOnly,
}

/// Typed statement made by the native admission owner about a source target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDependencyTarget<'a> {
    /// Complete selected ordinary Go source files for one resolved package.
    GoClosedPackage(&'a [NativeDependencyFile<'a>]),
    /// One exact static Python file origin under the selected roots.
    PythonStaticOrigin(NativeDependencyFile<'a>),
    /// The producer retained a reference without an exact source endpoint.
    Unresolved(NativeDependencyUnresolved),
}

/// One site and its admitted source-level target relation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDependencyEndpoint<'a> {
    /// Originating physical source location.
    pub occurrence: NativeDependencyOccurrence<'a>,
    /// Exact scoped target evidence or an explicit unresolved reason.
    pub target: NativeDependencyTarget<'a>,
}

/// One already admitted, single-language native result.
///
/// The exact owner constructs this from typed admitted facts. This API does
/// not deserialize external assertions, infer completeness, or perform native
/// compilation, lookup, or semantic evaluation.
pub struct NativeDependencyBatch<'a> {
    /// Admitted source-dependency observer family.
    pub language: NativeDependencyLanguage,
    /// Exact context from the admitted producer's result.
    pub context: NativeDependencyContext<'a>,
    /// Exact retained producer receipt identity.
    pub observation_sha256: &'a str,
    /// Directional occurrences and targets already admitted by that producer.
    pub endpoints: &'a [NativeDependencyEndpoint<'a>],
}

/// Exact ownership evidence for one endpoint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum NativeEndpointOwnership {
    /// Every source file belongs to the same declared Fortress Module.
    Declared {
        /// Independently resolved Module identity.
        module: String,
    },
    /// The exact files share an observer-owned mechanical territory.
    Scaffold {
        /// Mechanical analysis territory, with no implied declaration.
        territory: String,
    },
    /// The endpoint spans multiple owners or conflicted on an individual file.
    ManyOwned {
        /// All distinct owner/authority pairs found in the admitted relation.
        owners: Vec<NativeEndpointOwner>,
        /// Exact paths for which that relation gave no owner.
        unowned_paths: Vec<String>,
    },
    /// At least one exact source file has no supported owner.
    OwnershipUnavailable {
        /// Known owners of remaining exact files, if any.
        owners: Vec<NativeEndpointOwner>,
        /// Exact paths for which that relation gave no owner.
        unowned_paths: Vec<String>,
    },
}

/// One owner and the authority that supports it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeEndpointOwner {
    owner: String,
    authority: SourceOwnershipAuthority,
}

/// Scoped source-level target retained for review.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeDependencySiteTarget<'a> {
    /// Complete exact Go package evidence.
    GoClosedPackage {
        /// Exact files selected by the native context.
        files: Vec<NativeDependencyFile<'a>>,
        /// Ownership of the complete set of selected package files.
        ownership: NativeEndpointOwnership,
    },
    /// File candidate in the scoped Python source lookup.
    PythonStaticOrigin {
        /// Exact selected candidate file.
        file: NativeDependencyFile<'a>,
        /// Ownership of that file as established by the chosen authority.
        ownership: NativeEndpointOwnership,
    },
    /// Lookup emitted no exact file endpoint.
    Unresolved {
        /// Retained scoped reason for the unresolved result.
        reason: NativeDependencyUnresolved,
    },
}

impl NativeDependencySiteTarget<'_> {
    fn ownership(&self) -> Option<&NativeEndpointOwnership> {
        match self {
            Self::GoClosedPackage { ownership, .. }
            | Self::PythonStaticOrigin { ownership, .. } => Some(ownership),
            Self::Unresolved { .. } => None,
        }
    }
}

/// One occurrence, independently bound ownership and scoped directional target.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeDependencySite<'a> {
    occurrence: NativeDependencyOccurrence<'a>,
    source_ownership: NativeEndpointOwnership,
    target: NativeDependencySiteTarget<'a>,
}

impl<'a> NativeDependencySite<'a> {
    /// Returns the exact source occurrence of this directional relationship.
    #[must_use]
    pub const fn occurrence(&self) -> NativeDependencyOccurrence<'a> {
        self.occurrence
    }

    /// Returns the independently resolved source ownership disposition.
    #[must_use]
    pub const fn source_ownership(&self) -> &NativeEndpointOwnership {
        &self.source_ownership
    }

    /// Returns the bounded native target evidence and its ownership disposition.
    #[must_use]
    pub const fn target(&self) -> &NativeDependencySiteTarget<'a> {
        &self.target
    }
}

/// Versioned native adapter result and normalized positive source relations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeDependencyProjection<'a> {
    adapter_version: &'static str,
    context: NativeDependencyContext<'a>,
    language: NativeDependencyLanguage,
    observation_sha256: &'a str,
    coverage: &'static str,
    sites: Vec<NativeDependencySite<'a>>,
    observation: ObservedImplementation,
}

impl<'a> NativeDependencyProjection<'a> {
    /// Returns the independently checked source and authority context.
    #[must_use]
    pub const fn context(&self) -> NativeDependencyContext<'a> {
        self.context
    }

    /// Returns scoped native relationships and explicit nonresolutions.
    #[must_use]
    pub fn sites(&self) -> &[NativeDependencySite<'a>] {
        &self.sites
    }

    /// Returns the existing canonical observation model for these scoped facts.
    ///
    /// This projection supplies positive source evidence only. Unsupported
    /// endpoints, runtime behavior, and absence of dependency remain unproven.
    #[must_use]
    pub const fn observation(&self) -> &ObservedImplementation {
        &self.observation
    }
}

/// Failure at the exact, bounded native dependency adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDependencyAdapterError {
    /// Expected and admitted exact authority, context or snapshot do not match.
    BindingMismatch,
    /// Source path, coordinates, language or target shape are invalid.
    InvalidEndpoint,
    /// The admitted byte identity fails verification against immutable source.
    SourceIdentityMismatch,
    /// The admitted batch exceeds the adapter's bounded operational scope.
    ResourceLimit,
}

impl std::fmt::Display for NativeDependencyAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BindingMismatch => {
                "native dependency binding differs from selected exact context"
            }
            Self::InvalidEndpoint => "invalid native dependency endpoint",
            Self::SourceIdentityMismatch => {
                "native dependency endpoint differs from immutable source"
            }
            Self::ResourceLimit => "native dependency adapter resource limit exceeded",
        })
    }
}

impl std::error::Error for NativeDependencyAdapterError {}

type Failure = NativeDependencyAdapterError;

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

struct SiteCursor<'a> {
    path: &'a str,
    offset: usize,
    line: usize,
    column: usize,
}

struct VerifiedInventory<'a, 'source> {
    input: &'source ImplementationObservationInput,
    language: NativeDependencyLanguage,
    cursor: Option<SiteCursor<'a>>,
    verified: BTreeMap<&'a str, (&'a str, &'source str)>,
    bytes: usize,
}

impl<'a, 'source> VerifiedInventory<'a, 'source> {
    fn file(&mut self, observed: NativeDependencyFile<'a>) -> Result<&'source str, Failure> {
        if Path::new(observed.path).extension() != Some(OsStr::new(self.language.extension()))
            || observed.path.len() > MAX_PATH_BYTES
            || !crate::observation::is_canonical_relative_path(observed.path)
            || !valid_digest(observed.sha256)
        {
            return Err(Failure::InvalidEndpoint);
        }
        if let Some(&(sha, text)) = self.verified.get(observed.path) {
            return if sha == observed.sha256 {
                Ok(text)
            } else {
                Err(Failure::SourceIdentityMismatch)
            };
        }
        let files = self.input.files();
        let first = files.partition_point(|file| file.path() < observed.path);
        let file = files
            .get(first)
            .filter(|file| file.path() == observed.path)
            .ok_or(Failure::SourceIdentityMismatch)?;
        if files
            .get(first + 1)
            .is_some_and(|other| other.path() == observed.path)
            || file.expected_sha256 != observed.sha256
        {
            return Err(Failure::SourceIdentityMismatch);
        }
        self.bytes = self
            .bytes
            .checked_add(file.bytes.len())
            .ok_or(Failure::ResourceLimit)?;
        if self.verified.len() >= MAX_ENDPOINTS || self.bytes > MAX_ENDPOINT_BYTES {
            return Err(Failure::ResourceLimit);
        }
        let bytes = file
            .verified_bytes()
            .map_err(|_| Failure::SourceIdentityMismatch)?;
        let text = std::str::from_utf8(bytes).map_err(|_| Failure::InvalidEndpoint)?;
        self.verified.insert(observed.path, (observed.sha256, text));
        Ok(text)
    }

    fn site(
        &mut self,
        occurrence: NativeDependencyOccurrence<'a>,
    ) -> Result<SourceLocation, Failure> {
        let text = self.file(occurrence.file)?;
        if occurrence.reference.is_empty()
            || occurrence.reference.len() > MAX_REFERENCE_BYTES
            || occurrence.reference.chars().any(char::is_control)
            || text
                .get(occurrence.start_byte..occurrence.end_byte)
                .is_none_or(str::is_empty)
        {
            return Err(Failure::InvalidEndpoint);
        }
        // The batch is processed in physical occurrence order. Each source
        // prefix contributes to the location count at most once.
        let mut cursor = self
            .cursor
            .take()
            .filter(|prior| prior.path == occurrence.file.path)
            .unwrap_or(SiteCursor {
                path: occurrence.file.path,
                offset: 0,
                line: 1,
                column: 1,
            });
        let next = &text.as_bytes()[cursor.offset..occurrence.start_byte];
        cursor.column += next.len();
        for (index, &byte) in next.iter().enumerate() {
            if byte == b'\n' {
                cursor.line += 1;
                cursor.column = next.len() - index;
            }
        }
        cursor.offset = occurrence.start_byte;
        let line = u32::try_from(cursor.line).map_err(|_| Failure::ResourceLimit)?;
        let column = u32::try_from(cursor.column).map_err(|_| Failure::ResourceLimit)?;
        self.cursor = Some(cursor);
        Ok(SourceLocation::new(line, column))
    }

    fn target(
        &mut self,
        language: NativeDependencyLanguage,
        selected: NativeDependencyTarget<'a>,
    ) -> Result<NativeDependencySiteTarget<'a>, Failure> {
        match (language, selected) {
            (NativeDependencyLanguage::Go, NativeDependencyTarget::GoClosedPackage(files)) => {
                if files.len() > MAX_PACKAGE_FILES {
                    return Err(Failure::ResourceLimit);
                }
                let mut files = files.to_vec();
                files.sort_unstable();
                if files.is_empty() || files.windows(2).any(|pair| pair[0].path == pair[1].path) {
                    return Err(Failure::InvalidEndpoint);
                }
                for file in &files {
                    self.file(*file)?;
                }
                let ownership = endpoint_ownership(self.input, &files);
                Ok(NativeDependencySiteTarget::GoClosedPackage { files, ownership })
            }
            (
                NativeDependencyLanguage::Python,
                NativeDependencyTarget::PythonStaticOrigin(file),
            ) => {
                self.file(file)?;
                let ownership = endpoint_ownership(self.input, &[file]);
                Ok(NativeDependencySiteTarget::PythonStaticOrigin { file, ownership })
            }
            (_, NativeDependencyTarget::Unresolved(reason)) => {
                Ok(NativeDependencySiteTarget::Unresolved { reason })
            }
            _ => Err(Failure::InvalidEndpoint),
        }
    }
}

fn endpoint_ownership(
    input: &ImplementationObservationInput,
    files: &[NativeDependencyFile<'_>],
) -> NativeEndpointOwnership {
    let authorities = input.ownerships();
    let mut owners = BTreeSet::new();
    let mut unowned_paths = Vec::new();
    for file in files {
        let first = authorities.partition_point(|known| known.source_path() < file.path);
        let end = authorities.partition_point(|known| known.source_path() <= file.path);
        if first == end {
            unowned_paths.push(file.path.to_owned());
        }
        owners.extend(
            authorities[first..end]
                .iter()
                .map(|owner| NativeEndpointOwner {
                    owner: owner.owner().into(),
                    authority: owner.authority(),
                }),
        );
    }
    let mut owners: Vec<_> = owners.into_iter().collect();
    if owners.len() > 1 {
        NativeEndpointOwnership::ManyOwned {
            owners,
            unowned_paths,
        }
    } else if !unowned_paths.is_empty() {
        NativeEndpointOwnership::OwnershipUnavailable {
            owners,
            unowned_paths,
        }
    } else {
        let owner = owners
            .pop()
            .expect("verified endpoint has at least one ownership input");
        match owner.authority {
            SourceOwnershipAuthority::DeclaredModule => NativeEndpointOwnership::Declared {
                module: owner.owner,
            },
            SourceOwnershipAuthority::CargoAnalysisTerritory => NativeEndpointOwnership::Scaffold {
                territory: owner.owner,
            },
        }
    }
}

fn native_fact(
    site: &NativeDependencySite<'_>,
    language: NativeDependencyLanguage,
    location: SourceLocation,
) -> Option<ImplementationObservation> {
    let NativeEndpointOwnership::Declared { module: source } = &site.source_ownership else {
        return None;
    };
    let (classification, target_module, resolution) = match site.target.ownership() {
        Some(NativeEndpointOwnership::Declared { module }) => (
            TargetClassification::GovernedModule,
            Some(module.clone()),
            ResolutionStatus::Resolved,
        ),
        Some(NativeEndpointOwnership::Scaffold { territory }) => (
            TargetClassification::AnalysisTerritory,
            Some(territory.clone()),
            ResolutionStatus::Resolved,
        ),
        _ => (
            TargetClassification::Unresolved,
            None,
            ResolutionStatus::Unresolved,
        ),
    };
    let path = site.occurrence.file.path;
    let mut observation = ImplementationObservation::new(
        source,
        path,
        classification,
        target_module.clone(),
        None,
        Conditionality::Unestablished,
        ObservationProvenance::new(
            path,
            source,
            site.occurrence.reference,
            location,
            target_module,
        ),
        resolution,
    );
    observation.language = language.name().into();
    Some(observation)
}

fn issue(site: &NativeDependencySite<'_>) -> Option<ObservationIssue> {
    let detail = match (&site.source_ownership, site.target.ownership()) {
        (
            NativeEndpointOwnership::Declared { .. },
            Some(NativeEndpointOwnership::Declared { .. }),
        ) => return None,
        (NativeEndpointOwnership::ManyOwned { .. }, _) => {
            "native dependency source spans conflicting owners"
        }
        (NativeEndpointOwnership::OwnershipUnavailable { .. }, _) => {
            "native dependency source has no established owner"
        }
        (NativeEndpointOwnership::Scaffold { .. }, _) => {
            "native dependency source has only analysis ownership"
        }
        (_, Some(NativeEndpointOwnership::ManyOwned { .. })) => {
            "native dependency target spans multiple owners"
        }
        (_, Some(NativeEndpointOwnership::OwnershipUnavailable { .. })) => {
            "native dependency target ownership is incomplete"
        }
        (_, Some(NativeEndpointOwnership::Scaffold { .. })) => {
            "native dependency target has only analysis ownership"
        }
        (_, None) => "native dependency target is unresolved in the selected scope",
    };
    Some(ObservationIssue::new(
        ObservationIssueKind::Unsupported,
        site.occurrence.file.path,
        detail,
    ))
}

/// Projects already admitted directional native source-level facts through exact ownership.
///
/// An empty result conveys no conclusion about absence, runtime behavior or
/// governed certification. Callers must select the expected binding and exact
/// ownership inventory independently of the native result.
///
/// # Errors
///
/// Rejects mismatched context, stale source or content identities, malformed
/// endpoints, and resource excess. No positive fact is returned on failure.
pub fn adapt_native_dependencies<'a>(
    input: &ImplementationObservationInput,
    expected: NativeDependencyContext<'_>,
    admitted: &NativeDependencyBatch<'a>,
) -> Result<NativeDependencyProjection<'a>, Failure> {
    if expected != admitted.context
        || input.snapshot_fingerprint() != expected.snapshot_fingerprint
        || ![
            expected.snapshot_fingerprint,
            expected.source_view_sha256,
            expected.authority_sha256,
            expected.context_sha256,
            admitted.observation_sha256,
        ]
        .into_iter()
        .all(valid_digest)
    {
        return Err(Failure::BindingMismatch);
    }
    if admitted.endpoints.len() > MAX_SITES {
        return Err(Failure::ResourceLimit);
    }
    let mut inventory = VerifiedInventory {
        input,
        language: admitted.language,
        verified: BTreeMap::new(),
        cursor: None,
        bytes: 0,
    };
    let mut sites = BTreeMap::new();
    let mut facts = Vec::new();
    let mut issues = Vec::new();
    let mut endpoints: Vec<_> = admitted.endpoints.iter().collect();
    endpoints.sort_unstable_by_key(|endpoint| endpoint.occurrence);
    for endpoint in endpoints {
        let location = inventory.site(endpoint.occurrence)?;
        let site = NativeDependencySite {
            occurrence: endpoint.occurrence,
            source_ownership: endpoint_ownership(input, &[endpoint.occurrence.file]),
            target: inventory.target(admitted.language, endpoint.target)?,
        };
        if let Some(prior) = sites.get(&site.occurrence) {
            if prior != &site {
                return Err(Failure::InvalidEndpoint);
            }
            continue;
        }
        if let Some(fact) = native_fact(&site, admitted.language, location) {
            facts.push(fact);
        }
        if let Some(issue) = issue(&site) {
            issues.push(issue);
        }
        sites.insert(site.occurrence, site);
    }
    Ok(NativeDependencyProjection {
        adapter_version: VERSION,
        context: admitted.context,
        language: admitted.language,
        observation_sha256: admitted.observation_sha256,
        coverage: "positive_scoped_source_only_runtime_and_absence_unestablished",
        sites: sites.into_values().collect(),
        observation: ObservedImplementation::from_facts(
            expected.snapshot_fingerprint,
            admitted.language.analyzer(),
            VERSION,
            facts,
            issues,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::implementation_observation::{
        SnapshotBoundFile, SourceOwnership, SourceOwnershipBasis,
    };

    /// `T-NATIVE-DEPENDENCY-SCAFFOLD-001`
    /// Fortress classification: infrastructure
    #[test]
    fn analysis_scaffold_stays_out_of_governed_dependency_map() {
        let fingerprint = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let file =
            SnapshotBoundFile::from_bytes("src/main.go", "package main\nimport \"scaffold\"\n");
        let target = SnapshotBoundFile::from_bytes("dep/lib.go", "package dep\n");
        let source_digest = file.expected_sha256.clone();
        let target_digest = target.expected_sha256.clone();
        let owned = SourceOwnership {
            source_path: "src/main.go".into(),
            owner: "AF-APP-0001".into(),
            territory_path: "src".into(),
            authority: SourceOwnershipAuthority::DeclaredModule,
            basis: SourceOwnershipBasis::LogicalPathBinding,
        };
        let scaffold = SourceOwnership {
            source_path: "dep/lib.go".into(),
            owner: "SRC-ANALYSIS-CARGO-0001".into(),
            territory_path: "dep".into(),
            authority: SourceOwnershipAuthority::CargoAnalysisTerritory,
            basis: SourceOwnershipBasis::CargoAnalysisTerritory,
        };
        let input = ImplementationObservationInput::new_with_ownership(
            fingerprint,
            vec![file, target],
            vec![owned, scaffold],
        );
        let context = NativeDependencyContext {
            snapshot_fingerprint: fingerprint,
            source_view_sha256: fingerprint,
            authority_sha256: fingerprint,
            context_sha256: fingerprint,
        };
        let targets = [NativeDependencyFile {
            path: "dep/lib.go",
            sha256: &target_digest,
        }];
        let endpoint = NativeDependencyEndpoint {
            occurrence: NativeDependencyOccurrence {
                file: NativeDependencyFile {
                    path: "src/main.go",
                    sha256: &source_digest,
                },
                start_byte: 21,
                end_byte: 29,
                reference: "scaffold",
            },
            target: NativeDependencyTarget::GoClosedPackage(&targets),
        };
        let slots = [endpoint];
        let result = adapt_native_dependencies(
            &input,
            context,
            &NativeDependencyBatch {
                language: NativeDependencyLanguage::Go,
                context,
                observation_sha256: fingerprint,
                endpoints: &slots,
            },
        )
        .unwrap();
        assert!(
            matches!(result.sites()[0].target(), NativeDependencySiteTarget::GoClosedPackage {
            ownership: NativeEndpointOwnership::Scaffold { territory }, ..
        } if territory == "SRC-ANALYSIS-CARGO-0001")
        );
        assert!(result.observation().module_dependencies().is_empty());
        assert_eq!(
            result.observation().observations()[0].target_classification(),
            TargetClassification::AnalysisTerritory
        );
        assert_eq!(result.observation().issues().len(), 1);
    }
}
