//! Declared Fortress architecture loading and dependency evaluation.
//!
//! This module validates architecture declarations and evaluates their declared
//! component graph. It does not infer dependencies from repository contents or
//! create certification evidence.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Deserialize;

use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};
use crate::identity::{StableId, StableIdError};

/// Current supported architecture declaration schema family.
pub const ARCHITECTURE_SCHEMA_VERSION: u16 = 1;

/// Stable identity of the declared dependency-cycle rule.
pub const ARCH_DEPENDENCY_RULE_ID: &str = "ARCH-DEPENDENCY-001";

const ARCH_DEPENDENCY_REMEDIATION: &str = "Separate responsibilities to restore one-way dependency flow or model a genuinely inseparable strongly connected cluster as one component. A temporary exception requires a governed transition or exemption.";

/// A validated declared Fortress architecture model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ArchitectureManifest {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    zones: Vec<String>,
    components: Vec<ComponentDeclaration>,
    #[serde(default)]
    repository_artifacts: Vec<RepositoryArtifactDeclaration>,
}

impl ArchitectureManifest {
    /// Parses a JSON architecture declaration and validates its domain invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ArchitectureLoadError::Json`] for invalid JSON or structural
    /// type mismatches and [`ArchitectureLoadError::Model`] for invalid declared
    /// identities, zones, paths, uniqueness, or dependency targets.
    pub fn from_json_str(source: &str) -> Result<Self, ArchitectureLoadError> {
        let manifest: Self = serde_json::from_str(source).map_err(ArchitectureLoadError::Json)?;
        manifest.validate().map_err(ArchitectureLoadError::Model)?;
        Ok(manifest)
    }

    /// Validates the architecture declaration without observing source code.
    ///
    /// # Errors
    ///
    /// Returns [`ArchitectureModelError`] for the first deterministic model
    /// invariant violation.
    pub fn validate(&self) -> Result<(), ArchitectureModelError> {
        if self.schema.is_empty() {
            return Err(ArchitectureModelError::EmptyField("$schema"));
        }
        if self.schema_version != ARCHITECTURE_SCHEMA_VERSION {
            return Err(ArchitectureModelError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.zones.is_empty() {
            return Err(ArchitectureModelError::EmptyZones);
        }

        let mut zones = HashSet::with_capacity(self.zones.len());
        for zone in &self.zones {
            if !is_lower_name(zone) {
                return Err(ArchitectureModelError::InvalidZone(zone.clone().into()));
            }
            if !zones.insert(zone.as_str()) {
                return Err(ArchitectureModelError::DuplicateZone(zone.clone().into()));
            }
        }

        if self.components.is_empty() {
            return Err(ArchitectureModelError::EmptyComponents);
        }

        let mut component_ids = HashSet::with_capacity(self.components.len());
        for component in &self.components {
            StableId::parse(&component.id).map_err(|source| {
                ArchitectureModelError::InvalidIdentity {
                    field: "components.id",
                    value: component.id.clone().into(),
                    source,
                }
            })?;
            if !component_ids.insert(component.id.as_str()) {
                return Err(ArchitectureModelError::DuplicateComponent(
                    component.id.clone().into(),
                ));
            }
            if component.title.is_empty() {
                return Err(ArchitectureModelError::EmptyField("components.title"));
            }
            if !is_lower_name(&component.zone) {
                return Err(ArchitectureModelError::InvalidZone(
                    component.zone.clone().into(),
                ));
            }
            if !zones.contains(component.zone.as_str()) {
                return Err(ArchitectureModelError::UnknownZone {
                    component: component.id.clone().into(),
                    zone: component.zone.clone().into(),
                });
            }
            validate_component_paths(component)?;
            validate_dependencies(component)?;
        }

        let mut artifact_paths = HashSet::with_capacity(self.repository_artifacts.len());
        for artifact in &self.repository_artifacts {
            if !is_exact_relative_path(&artifact.path) {
                return Err(ArchitectureModelError::InvalidRepositoryArtifactPath(
                    artifact.path.clone().into(),
                ));
            }
            if !artifact_paths.insert(artifact.path.as_str()) {
                return Err(ArchitectureModelError::DuplicateRepositoryArtifactPath(
                    artifact.path.clone().into(),
                ));
            }
            StableId::parse(&artifact.owner).map_err(|source| {
                ArchitectureModelError::InvalidIdentity {
                    field: "repository_artifacts.owner",
                    value: artifact.owner.clone().into(),
                    source,
                }
            })?;
            if !component_ids.contains(artifact.owner.as_str()) {
                return Err(ArchitectureModelError::UnknownRepositoryArtifactOwner {
                    path: artifact.path.clone().into(),
                    owner: artifact.owner.clone().into(),
                });
            }
        }
        for component in &self.components {
            for dependency in &component.depends_on {
                if !component_ids.contains(dependency.as_str()) {
                    return Err(ArchitectureModelError::UnknownDependency {
                        component: component.id.clone().into(),
                        dependency: dependency.clone().into(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Returns the declared architecture zones.
    #[must_use]
    pub fn zones(&self) -> &[String] {
        &self.zones
    }

    /// Returns the declared architecture components.
    #[must_use]
    pub fn components(&self) -> &[ComponentDeclaration] {
        &self.components
    }

    /// Returns explicitly classified repository-level or generated artifacts.
    #[must_use]
    pub fn repository_artifacts(&self) -> &[RepositoryArtifactDeclaration] {
        &self.repository_artifacts
    }

    /// Evaluates draft rule `ARCH-DEPENDENCY-001` against declared edges.
    ///
    /// Returns the first deterministic directed cycle, if one exists. A `None`
    /// result describes only the declared graph and is not a certification PASS.
    ///
    /// # Errors
    ///
    /// Returns [`FindingError`] if normalized finding construction fails.
    pub fn evaluate_acyclic_dependencies(
        &self,
        standard_edition: &str,
    ) -> Result<Option<CanonicalFinding>, FindingError> {
        let mut adjacency = BTreeMap::new();
        for component in &self.components {
            let mut dependencies: Vec<&str> =
                component.depends_on.iter().map(String::as_str).collect();
            dependencies.sort_unstable();
            adjacency.insert(component.id.as_str(), dependencies);
        }

        let mut states = HashMap::with_capacity(self.components.len());
        for start in adjacency.keys().copied() {
            if states.contains_key(start) {
                continue;
            }

            states.insert(start, VisitState::Visiting);
            let mut path = vec![start];
            let mut stack = vec![(start, 0_usize)];

            while let Some(&(node, next_offset)) = stack.last() {
                let dependencies = adjacency.get(node).map_or(&[][..], Vec::as_slice);
                let Some(&dependency) = dependencies.get(next_offset) else {
                    states.insert(node, VisitState::Complete);
                    stack.pop();
                    path.pop();
                    continue;
                };

                if let Some(last) = stack.last_mut() {
                    last.1 += 1;
                }
                match states
                    .get(dependency)
                    .copied()
                    .unwrap_or(VisitState::Unseen)
                {
                    VisitState::Unseen => {
                        states.insert(dependency, VisitState::Visiting);
                        path.push(dependency);
                        stack.push((dependency, 0));
                    }
                    VisitState::Visiting => {
                        if let Some(cycle_start) =
                            path.iter().position(|identity| *identity == dependency)
                        {
                            let mut entities: Vec<String> = path
                                .iter()
                                .skip(cycle_start)
                                .map(|identity| (*identity).to_owned())
                                .collect();
                            entities.push(dependency.to_owned());
                            let route = entities.join(" -> ");
                            let definition = RuleFindingDefinition::new(
                                ARCH_DEPENDENCY_RULE_ID,
                                1,
                                FindingCategory::Architecture,
                                ARCH_DEPENDENCY_REMEDIATION,
                            )?;
                            let occurrence = FindingOccurrence::new(
                                entities,
                                FindingLocation::none(),
                                format!(
                                    "Declared component dependency graph contains a cycle: {route}."
                                ),
                            )?;
                            let evaluator = EvaluatorProvenance::new(
                                "fortress-core/architecture",
                                env!("CARGO_PKG_VERSION"),
                            )?;
                            return CanonicalFinding::failure(
                                definition,
                                occurrence,
                                evaluator,
                                standard_edition,
                                None,
                            )
                            .map(Some);
                        }
                    }
                    VisitState::Complete => {}
                }
            }
        }

        Ok(None)
    }
}

/// An exact repository path whose ownership and non-source classification are declared.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RepositoryArtifactDeclaration {
    path: String,
    owner: String,
    classification: RepositoryArtifactClassification,
    required: bool,
}

impl RepositoryArtifactDeclaration {
    /// Returns the exact canonical repository-relative artifact path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the declared architectural owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the declared artifact class.
    #[must_use]
    pub const fn classification(&self) -> RepositoryArtifactClassification {
        self.classification
    }

    /// Returns whether observation must contain this exact artifact.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// Supported explicit non-source repository artifact classes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum RepositoryArtifactClassification {
    /// A repository-wide build, policy, automation, or descriptive record.
    RepositoryMetadata,
    /// A generated artifact retained under a declared authority.
    Generated,
    /// Ephemeral execution state that must not occupy governed source roots.
    RuntimeState,
}

impl RepositoryArtifactClassification {
    /// Returns the canonical serialized classification spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepositoryMetadata => "repository-metadata",
            Self::Generated => "generated",
            Self::RuntimeState => "runtime-state",
        }
    }
}

/// One validated component declaration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ComponentDeclaration {
    id: String,
    title: String,
    zone: String,
    paths: Vec<String>,
    depends_on: Vec<String>,
}

impl ComponentDeclaration {
    /// Returns the stable component identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the component display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the component's declared architecture zone.
    #[must_use]
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Returns repository-relative paths owned by the component.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Returns stable identities of declared dependency targets.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.depends_on
    }
}

/// Explains why an architecture declaration could not be loaded.
#[derive(Debug)]
pub enum ArchitectureLoadError {
    /// JSON parsing or structural deserialization failed.
    Json(serde_json::Error),
    /// Parsed data violated a declared architecture invariant.
    Model(ArchitectureModelError),
}

impl Display for ArchitectureLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "architecture JSON is invalid: {error}"),
            Self::Model(error) => write!(formatter, "architecture model is invalid: {error}"),
        }
    }
}

impl Error for ArchitectureLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Model(error) => Some(error),
        }
    }
}

/// Explains a violated declared architecture invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchitectureModelError {
    /// The schema-family version is unsupported.
    UnsupportedSchemaVersion(u16),
    /// A required string field was empty.
    EmptyField(&'static str),
    /// No architecture zones were declared.
    EmptyZones,
    /// A zone name did not use canonical lowercase syntax.
    InvalidZone(Box<str>),
    /// A zone name was repeated.
    DuplicateZone(Box<str>),
    /// No components were declared.
    EmptyComponents,
    /// A component or dependency identity was invalid.
    InvalidIdentity {
        /// Field containing the invalid identity.
        field: &'static str,
        /// Invalid serialized identity.
        value: Box<str>,
        /// Stable identity validation failure.
        source: StableIdError,
    },
    /// A component identity was repeated.
    DuplicateComponent(Box<str>),
    /// A component referenced a zone absent from the zone registry.
    UnknownZone {
        /// Component containing the reference.
        component: Box<str>,
        /// Unregistered zone name.
        zone: Box<str>,
    },
    /// A component declared no owned path.
    EmptyPaths(Box<str>),
    /// A component path was not a canonical repository-relative path or prefix.
    InvalidPath {
        /// Component containing the invalid path.
        component: Box<str>,
        /// Invalid path value.
        path: Box<str>,
    },
    /// A component path was repeated.
    DuplicatePath {
        /// Component containing the duplicate.
        component: Box<str>,
        /// Repeated path value.
        path: Box<str>,
    },
    /// A dependency identity was repeated within one component.
    DuplicateDependency {
        /// Component containing the duplicate.
        component: Box<str>,
        /// Repeated dependency identity.
        dependency: Box<str>,
    },
    /// A dependency target was absent from the component registry.
    UnknownDependency {
        /// Component containing the reference.
        component: Box<str>,
        /// Missing dependency identity.
        dependency: Box<str>,
    },
    /// A repository artifact path was not exact, canonical, and relative.
    InvalidRepositoryArtifactPath(Box<str>),
    /// A repository artifact path was declared more than once.
    DuplicateRepositoryArtifactPath(Box<str>),
    /// A repository artifact referenced an undeclared component owner.
    UnknownRepositoryArtifactOwner {
        /// Exact declared artifact path.
        path: Box<str>,
        /// Missing component identity.
        owner: Box<str>,
    },
}

impl Display for ArchitectureModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "architecture schema version {version} is unsupported"
                )
            }
            Self::EmptyField(field) => write!(formatter, "field `{field}` must not be empty"),
            Self::EmptyZones => formatter.write_str("architecture must declare at least one zone"),
            Self::InvalidZone(zone) => write!(formatter, "zone `{zone}` has invalid syntax"),
            Self::DuplicateZone(zone) => write!(formatter, "zone `{zone}` is duplicated"),
            Self::EmptyComponents => {
                formatter.write_str("architecture must declare at least one component")
            }
            Self::InvalidIdentity {
                field,
                value,
                source,
            } => write!(
                formatter,
                "field `{field}` contains invalid identity `{value}`: {source}"
            ),
            Self::DuplicateComponent(component) => {
                write!(formatter, "component `{component}` is duplicated")
            }
            Self::UnknownZone { component, zone } => {
                write!(
                    formatter,
                    "component `{component}` uses unknown zone `{zone}`"
                )
            }
            Self::EmptyPaths(component) => {
                write!(
                    formatter,
                    "component `{component}` must declare at least one path"
                )
            }
            Self::InvalidPath { component, path } => {
                write!(
                    formatter,
                    "component `{component}` has invalid path `{path}`"
                )
            }
            Self::DuplicatePath { component, path } => {
                write!(formatter, "component `{component}` repeats path `{path}`")
            }
            Self::DuplicateDependency {
                component,
                dependency,
            } => write!(
                formatter,
                "component `{component}` repeats dependency `{dependency}`"
            ),
            Self::UnknownDependency {
                component,
                dependency,
            } => write!(
                formatter,
                "component `{component}` references unknown dependency `{dependency}`"
            ),
            Self::InvalidRepositoryArtifactPath(path) => write!(
                formatter,
                "repository artifact path `{path}` is not exact, canonical, and relative"
            ),
            Self::DuplicateRepositoryArtifactPath(path) => {
                write!(formatter, "repository artifact path `{path}` is duplicated")
            }
            Self::UnknownRepositoryArtifactOwner { path, owner } => write!(
                formatter,
                "repository artifact `{path}` references unknown owner `{owner}`"
            ),
        }
    }
}

impl Error for ArchitectureModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIdentity { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitState {
    Unseen,
    Visiting,
    Complete,
}

fn validate_component_paths(
    component: &ComponentDeclaration,
) -> Result<(), ArchitectureModelError> {
    if component.paths.is_empty() {
        return Err(ArchitectureModelError::EmptyPaths(
            component.id.clone().into(),
        ));
    }

    let mut paths = HashSet::with_capacity(component.paths.len());
    for path in &component.paths {
        if !is_relative_path_or_prefix(path) {
            return Err(ArchitectureModelError::InvalidPath {
                component: component.id.clone().into(),
                path: path.clone().into(),
            });
        }
        if !paths.insert(path.as_str()) {
            return Err(ArchitectureModelError::DuplicatePath {
                component: component.id.clone().into(),
                path: path.clone().into(),
            });
        }
    }
    Ok(())
}

fn validate_dependencies(component: &ComponentDeclaration) -> Result<(), ArchitectureModelError> {
    let mut dependencies = HashSet::with_capacity(component.depends_on.len());
    for dependency in &component.depends_on {
        StableId::parse(dependency).map_err(|source| ArchitectureModelError::InvalidIdentity {
            field: "components.depends_on",
            value: dependency.clone().into(),
            source,
        })?;
        if !dependencies.insert(dependency.as_str()) {
            return Err(ArchitectureModelError::DuplicateDependency {
                component: component.id.clone().into(),
                dependency: dependency.clone().into(),
            });
        }
    }
    Ok(())
}

fn is_lower_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_relative_path_or_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_path = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if value.is_empty() || value.starts_with('/') || value.contains('\\') || drive_path {
        return false;
    }

    let path = value.strip_suffix('/').unwrap_or(value);
    !path.is_empty()
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn is_exact_relative_path(value: &str) -> bool {
    is_relative_path_or_prefix(value) && !value.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::{ArchitectureLoadError, ArchitectureManifest, ArchitectureModelError};

    const VALID: &str = r#"{
        "$schema": "urn:fortress:schema:v1:architecture",
        "schema_version": 1,
        "zones": ["core"],
        "components": [{
            "id": "AF-CORE-0001",
            "title": "Core",
            "zone": "core",
            "paths": ["core/"],
            "depends_on": []
        }]
    }"#;

    /// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-001`
    #[test]
    fn loader_rejects_invalid_and_unknown_dependency_identities() {
        let invalid = VALID.replace("AF-CORE-0001", "af-core");
        assert!(matches!(
            ArchitectureManifest::from_json_str(&invalid),
            Err(ArchitectureLoadError::Model(
                ArchitectureModelError::InvalidIdentity { .. }
            ))
        ));

        let unknown = VALID.replace("\"depends_on\": []", "\"depends_on\": [\"AF-MISSING\"]");
        assert!(matches!(
            ArchitectureManifest::from_json_str(&unknown),
            Err(ArchitectureLoadError::Model(
                ArchitectureModelError::UnknownDependency { .. }
            ))
        ));
    }

    /// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-002`
    #[test]
    fn loader_rejects_invalid_zones_and_paths() {
        let invalid_zone = VALID.replace("\"zone\": \"core\"", "\"zone\": \"Core\"");
        assert!(matches!(
            ArchitectureManifest::from_json_str(&invalid_zone),
            Err(ArchitectureLoadError::Model(
                ArchitectureModelError::InvalidZone(_)
            ))
        ));

        let invalid_path = VALID.replace("core/", "../core");
        assert!(matches!(
            ArchitectureManifest::from_json_str(&invalid_path),
            Err(ArchitectureLoadError::Model(
                ArchitectureModelError::InvalidPath { .. }
            ))
        ));
    }

    /// `T-AF-ARCHITECTURE-EVALUATION-0001-R01-003`
    #[test]
    fn loader_rejects_duplicate_components_paths_and_dependencies() {
        let mut manifest: ArchitectureManifest =
            serde_json::from_str(VALID).expect("fixture must deserialize");
        manifest.components.push(manifest.components[0].clone());
        assert!(matches!(
            manifest.validate(),
            Err(ArchitectureModelError::DuplicateComponent(_))
        ));

        let mut manifest: ArchitectureManifest =
            serde_json::from_str(VALID).expect("fixture must deserialize");
        manifest.components[0].paths.push("core/".into());
        assert!(matches!(
            manifest.validate(),
            Err(ArchitectureModelError::DuplicatePath { .. })
        ));

        let duplicate_dependency = VALID.replace(
            "\"depends_on\": []",
            "\"depends_on\": [\"AF-CORE-0001\", \"AF-CORE-0001\"]",
        );
        assert!(matches!(
            ArchitectureManifest::from_json_str(&duplicate_dependency),
            Err(ArchitectureLoadError::Model(
                ArchitectureModelError::DuplicateDependency { .. }
            ))
        ));
    }
}
