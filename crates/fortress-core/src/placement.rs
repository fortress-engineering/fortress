//! Evaluation of project-declared repository placement constraints.

use crate::architecture::{ArchitectureManifest, RepositoryStructureDeclaration};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of declared repository placement integrity.
pub const REPO_PLACEMENT_RULE_ID: &str = "REPO-PLACEMENT-001";

const REMEDIATION: &str = "Move the path into a declared top-level and owned structural root, declare a defensible project-specific placement, remove prohibited generated/runtime state from source, or restore the exact canonical Fortress-controlled path spelling.";

/// Evaluates observed paths against the repository structure the project claims.
///
/// The rule uses only project-declared allowed top-level roots, source roots,
/// artifact classifications, component ownership paths, and canonical paths.
/// It contains no ecosystem-wide fixed directory tree.
///
/// # Errors
///
/// Returns [`FindingError`] if a normalized finding cannot be constructed.
pub fn evaluate_repository_placement(
    architecture: &ArchitectureManifest,
    observed_paths: &[String],
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let definition = RuleFindingDefinition::new(
        REPO_PLACEMENT_RULE_ID,
        1,
        FindingCategory::Repository,
        REMEDIATION,
    )?;
    let evaluator = EvaluatorProvenance::new("fortress-core/placement", env!("CARGO_PKG_VERSION"))?;
    let Some(structure) = architecture.repository_structure() else {
        return Ok(vec![make_finding(
            &definition,
            &evaluator,
            Vec::new(),
            FindingLocation::none(),
            "The project architecture declares no repository placement policy.".into(),
            standard_edition,
        )?]);
    };

    let mut findings = Vec::new();
    evaluate_observed_placement(
        architecture,
        structure,
        observed_paths,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    evaluate_canonical_paths(
        structure.canonical_paths(),
        observed_paths,
        &definition,
        &evaluator,
        standard_edition,
        &mut findings,
    )?;
    findings.sort();
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
fn evaluate_observed_placement(
    architecture: &ArchitectureManifest,
    structure: &RepositoryStructureDeclaration,
    observed_paths: &[String],
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for path in observed_paths {
        let artifact = architecture
            .repository_artifacts()
            .iter()
            .find(|artifact| artifact.path() == path);
        let owners = declared_owners(architecture, path);
        if owners.is_empty() {
            findings.push(path_finding(
                definition,
                evaluator,
                Vec::new(),
                path,
                format!("Observed path `{path}` is outside declared structural ownership."),
                standard_edition,
            )?);
        }
        if let Some((top_level, _)) = path.split_once('/') {
            if artifact.is_none()
                && !structure
                    .allowed_top_level()
                    .iter()
                    .any(|allowed| allowed == top_level)
            {
                findings.push(path_finding(
                    definition,
                    evaluator,
                    owners,
                    path,
                    format!(
                        "Observed path `{path}` occupies undeclared top-level island `{top_level}`."
                    ),
                    standard_edition,
                )?);
            }
        }
        if let Some(artifact) = artifact {
            let prohibited = structure
                .prohibited_artifact_classes_in_source()
                .contains(&artifact.classification());
            let in_source = structure
                .source_roots()
                .iter()
                .any(|root| path_matches(root, path));
            if prohibited && in_source {
                findings.push(path_finding(
                    definition,
                    evaluator,
                    vec![artifact.owner().to_owned()],
                    path,
                    format!(
                        "Declared {} artifact `{path}` is prohibited inside governed source roots.",
                        artifact.classification().as_str()
                    ),
                    standard_edition,
                )?);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_canonical_paths(
    canonical_paths: &[String],
    observed_paths: &[String],
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    standard_edition: &str,
    findings: &mut Vec<CanonicalFinding>,
) -> Result<(), FindingError> {
    for canonical in canonical_paths {
        if observed_paths.iter().any(|path| path == canonical) {
            continue;
        }
        if let Some(observed) = observed_paths
            .iter()
            .find(|path| path.eq_ignore_ascii_case(canonical))
        {
            findings.push(path_finding(
                definition,
                evaluator,
                Vec::new(),
                observed,
                format!(
                    "Fortress-controlled path `{observed}` must use canonical spelling `{canonical}`."
                ),
                standard_edition,
            )?);
        } else {
            findings.push(path_finding(
                definition,
                evaluator,
                Vec::new(),
                canonical,
                format!("Required canonical Fortress-controlled path `{canonical}` is absent."),
                standard_edition,
            )?);
        }
    }
    Ok(())
}

fn declared_owners(architecture: &ArchitectureManifest, path: &str) -> Vec<String> {
    let mut owners: Vec<String> = architecture
        .components()
        .iter()
        .filter(|component| {
            component
                .paths()
                .iter()
                .any(|declaration| path_matches(declaration, path))
        })
        .map(|component| component.id().to_owned())
        .chain(
            architecture
                .repository_artifacts()
                .iter()
                .filter(|artifact| artifact.path() == path)
                .map(|artifact| artifact.owner().to_owned()),
        )
        .collect();
    owners.sort();
    owners.dedup();
    owners
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

fn path_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    entities: Vec<String>,
    path: &str,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    make_finding(
        definition,
        evaluator,
        entities,
        FindingLocation::at_path(path)?,
        message,
        standard_edition,
    )
}

fn make_finding(
    definition: &RuleFindingDefinition,
    evaluator: &EvaluatorProvenance,
    entities: Vec<String>,
    location: FindingLocation,
    message: String,
    standard_edition: &str,
) -> Result<CanonicalFinding, FindingError> {
    CanonicalFinding::failure(
        definition.clone(),
        FindingOccurrence::new(entities, location, message)?,
        evaluator.clone(),
        standard_edition,
        None,
    )
}
