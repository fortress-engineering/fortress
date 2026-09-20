//! Explicit, machine-independent Rust analysis context.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Why a generated input cannot be represented in portable analysis context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramContextError {
    /// The generated input path is not portable repository-relative syntax.
    InvalidGeneratedPath(String),
    /// The supplied byte identity is not a lowercase SHA-256 digest.
    InvalidGeneratedDigest(String),
}

impl std::fmt::Display for ProgramContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProgramContextError {}

/// Distinguishes absent knowledge from a proven empty set or value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContextKnowledge<T> {
    /// The producer cannot establish the value from immutable inputs.
    Unknown,
    /// The producer established this value, which may be empty.
    Known(T),
}

/// One exact source input generated outside the read-only Rust frontend.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GeneratedInput {
    repository_relative_path: String,
    content_digest: String,
}

impl GeneratedInput {
    /// Records a generated input without including an absolute machine path.
    ///
    /// # Errors
    /// Returns an error for a nonportable path or invalid SHA-256 identity.
    pub fn new(
        path: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, ProgramContextError> {
        let path = path.into();
        let digest = digest.into();
        if !crate::observation::is_canonical_relative_path(&path) {
            return Err(ProgramContextError::InvalidGeneratedPath(path));
        }
        if digest.len() != 71
            || !digest.starts_with("sha256:")
            || !digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProgramContextError::InvalidGeneratedDigest(digest));
        }
        Ok(Self {
            repository_relative_path: path,
            content_digest: digest,
        })
    }
}

/// One package and target alternative with explicit feature and cfg knowledge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramPackageContext {
    package_identity: String,
    target_identity: String,
    features: ContextKnowledge<Vec<String>>,
    cfg: ContextKnowledge<Vec<String>>,
    dependency_resolution_digest: String,
}

impl ProgramPackageContext {
    /// Constructs one context alternative.
    #[must_use]
    pub fn new(
        package_identity: impl Into<String>,
        target_identity: impl Into<String>,
        mut features: ContextKnowledge<Vec<String>>,
        mut cfg: ContextKnowledge<Vec<String>>,
        dependency_resolution_digest: impl Into<String>,
    ) -> Self {
        for values in [&mut features, &mut cfg] {
            if let ContextKnowledge::Known(values) = values {
                values.sort();
                values.dedup();
            }
        }
        Self {
            package_identity: package_identity.into(),
            target_identity: target_identity.into(),
            features,
            cfg,
            dependency_resolution_digest: dependency_resolution_digest.into(),
        }
    }
}

/// The immutable frontend and configuration context of a semantic evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramContext {
    version: u16,
    language_frontend_id: String,
    semantic_version: String,
    toolchain_identity: ContextKnowledge<String>,
    packages: Vec<ProgramPackageContext>,
    target_platform: ContextKnowledge<String>,
    generated_inputs: ContextKnowledge<Vec<GeneratedInput>>,
    execution_scope: String,
    limitations: Vec<String>,
}

impl ProgramContext {
    /// Creates a canonical context without reading local machine state.
    #[must_use]
    pub fn new(
        language_frontend_id: impl Into<String>,
        semantic_version: impl Into<String>,
        packages: impl IntoIterator<Item = ProgramPackageContext>,
        toolchain_identity: ContextKnowledge<String>,
        mut generated_inputs: ContextKnowledge<Vec<GeneratedInput>>,
        execution_scope: impl Into<String>,
        limitations: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut packages = packages.into_iter().collect::<Vec<_>>();
        packages.sort();
        packages.dedup();
        if let ContextKnowledge::Known(inputs) = &mut generated_inputs {
            inputs.sort();
            inputs.dedup();
        }
        let mut limitations = limitations.into_iter().collect::<Vec<_>>();
        limitations.sort();
        limitations.dedup();
        Self {
            version: 1,
            language_frontend_id: language_frontend_id.into(),
            semantic_version: semantic_version.into(),
            toolchain_identity,
            packages,
            target_platform: ContextKnowledge::Unknown,
            generated_inputs,
            execution_scope: execution_scope.into(),
            limitations,
        }
    }

    /// Supplies an explicit platform known to the caller.
    #[must_use]
    pub fn with_target_platform(mut self, platform: ContextKnowledge<String>) -> Self {
        self.target_platform = platform;
        self
    }

    /// Serializes stable context bytes independently of checkout location.
    ///
    /// # Panics
    /// Panics only if the fixed in-memory context representation cannot be serialized.
    #[must_use]
    pub fn to_canonical_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).expect("context serializes");
        json.push('\n');
        json
    }

    /// Identifies all fields in this context.
    #[must_use]
    pub fn digest(&self) -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_json().as_bytes())
        )
    }

    /// Returns true only when all configuration dimensions needed by the frontend are known.
    #[must_use]
    pub fn configuration_known(&self) -> bool {
        self.limitations.is_empty()
            && matches!(self.target_platform, ContextKnowledge::Known(_))
            && matches!(self.generated_inputs, ContextKnowledge::Known(_))
            && self.packages.iter().all(|package| {
                matches!(package.features, ContextKnowledge::Known(_))
                    && matches!(package.cfg, ContextKnowledge::Known(_))
            })
    }
}
