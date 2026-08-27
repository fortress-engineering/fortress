//! Reconciliation of stabilized repository paths with declared owners.
//!
//! This evaluator consumes only contract-resolved Module territory and observed
//! path facts. It does not add ecosystem-specific filename exceptions or
//! redefine the governing standard rule.

use std::collections::BTreeSet;

use crate::architecture::ArchitectureManifest;
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of exact declared repository ownership.
pub const ARCH_OWNERSHIP_RULE_ID: &str = "ARCH-OWNERSHIP-001";

const REMEDIATION: &str = "Converge the path to one canonical Module territory, remove incompatible overlapping fixture declarations, and represent generated or repository-level material through its actual Module ownership.";

/// One deterministic observed-path-to-owner assignment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OwnershipAssignment {
    path: String,
    owner: String,
}

impl OwnershipAssignment {
    /// Returns the observed canonical repository-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the single declared architectural owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
}

/// Deterministic reconciliation output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipEvaluation {
    assignments: Vec<OwnershipAssignment>,
    findings: Vec<CanonicalFinding>,
}

impl OwnershipEvaluation {
    /// Returns canonical owner assignments sorted by path and owner.
    #[must_use]
    pub fn assignments(&self) -> &[OwnershipAssignment] {
        &self.assignments
    }

    /// Returns canonical ownership findings in global finding order.
    #[must_use]
    pub fn findings(&self) -> &[CanonicalFinding] {
        &self.findings
    }
}

/// Evaluates exact-one ownership for all stabilized governed paths.
///
/// Derived component paths match exact observed files. Specification fixtures
/// may also use a trailing `/` prefix to exercise orphan and overlap semantics.
///
/// # Errors
///
/// Returns [`FindingError`] only when deterministic normalized finding
/// construction fails after the architecture model and paths were validated.
pub fn evaluate_file_ownership(
    architecture: &ArchitectureManifest,
    observed_paths: &[String],
    standard_edition: &str,
) -> Result<OwnershipEvaluation, FindingError> {
    let definition = RuleFindingDefinition::new(
        ARCH_OWNERSHIP_RULE_ID,
        1,
        FindingCategory::Architecture,
        REMEDIATION,
    )?;
    let evaluator = EvaluatorProvenance::new("fortress-core/ownership", env!("CARGO_PKG_VERSION"))?;
    let mut assignments = Vec::new();
    let mut findings = Vec::new();

    evaluate_observed_paths(
        architecture,
        observed_paths,
        standard_edition,
        &definition,
        &evaluator,
        &mut assignments,
        &mut findings,
    )?;
    evaluate_required_declarations(
        architecture,
        observed_paths,
        standard_edition,
        &definition,
        &evaluator,
        &mut findings,
    )?;

    assignments.sort();
    findings.sort();
    Ok(OwnershipEvaluation {
        assignments,
        findings,
    })
}

#[allow(clippy::too_many_arguments)]
fn evaluate_observed_paths(
    architecture: &ArchitectureManifest,
    observed_paths: &[String],
    standard_edition: &str,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    assignments: &mut Vec<OwnershipAssignment>,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for path in observed_paths {
        let mut owners = BTreeSet::new();
        for component in architecture.components() {
            if component
                .paths()
                .iter()
                .any(|declaration| path_matches(declaration, path))
            {
                owners.insert(component.id().to_owned());
            }
        }
        match owners.len() {
            0 => findings.push(make_finding(
                definition,
                evaluator,
                Vec::new(),
                path,
                format!("Governed repository file `{path}` has no declared architectural owner."),
                standard_edition,
            )?),
            1 => {
                if let Some(owner) = owners.into_iter().next() {
                    assignments.push(OwnershipAssignment {
                        path: path.clone(),
                        owner,
                    });
                }
            }
            _ => {
                let owners: Vec<String> = owners.into_iter().collect();
                findings.push(make_finding(
                    definition,
                    evaluator,
                    owners.clone(),
                    path,
                    format!(
                        "Governed repository file `{path}` matches incompatible declared owners: {}.",
                        owners.join(", ")
                    ),
                    standard_edition,
                )?);
            }
        }
    }
    Ok(())
}

fn evaluate_required_declarations(
    architecture: &ArchitectureManifest,
    observed_paths: &[String],
    standard_edition: &str,
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for component in architecture.components() {
        for declaration in component.paths() {
            if !observed_paths
                .iter()
                .any(|path| path_matches(declaration, path))
            {
                let location = declaration.trim_end_matches('/');
                findings.push(make_finding(
                    definition,
                    evaluator,
                    vec![component.id().to_owned()],
                    location,
                    format!(
                        "Declared owned path `{declaration}` for `{}` does not exist in the governed observation.",
                        component.id()
                    ),
                    standard_edition,
                )?);
            }
        }
    }
    Ok(())
}

fn path_matches(declaration: &str, observed: &str) -> bool {
    declaration.strip_suffix('/').map_or_else(
        || observed == declaration,
        |prefix| {
            observed
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        },
    )
}

fn make_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    entities: Vec<String>,
    path: &str,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(entities, FindingLocation::at_path(path)?, message)?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}
