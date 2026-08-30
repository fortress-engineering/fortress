//! Standard evaluation of the canonical Project Filing System model.

pub(crate) const MODULE_RULE_SOURCE: &str = include_str!("../data/module_rule.json");

use crate::filing::{FilingSystemProfiles, ProjectFilingModel, analyze_project_filing_system};
use crate::finding::{
    CanonicalFinding, EvaluatorProvenance, FindingCategory, FindingError, FindingLocation,
    FindingOccurrence, RuleFindingDefinition,
};

/// Stable identity of the recursive Fortress Module and Element grammar.
pub const REPO_MODULE_RULE_ID: &str = "REPO-MODULE-001";

const REMEDIATION: &str = "Converge the path to the canonical Project Filing System grammar: retain README.md and contract.json at every Module root; keep project source files flat under code; place children only under mods; use the closed docs set; and use the shallowest valid Data/Info role, collection, version, and partition structure.";

/// Evaluates observed repository paths using the Standard-owned ecosystem profiles.
///
/// # Errors
///
/// Returns [`FindingError`] if a normalized Standard finding cannot be constructed.
pub fn evaluate_module_grammar(
    observed_paths: &[String],
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let profiles = FilingSystemProfiles::standard();
    evaluate_module_grammar_with_profiles(observed_paths, standard_edition, &profiles)
}

/// Evaluates observed paths with an explicit validated ecosystem profile registry.
///
/// This entry point supports language-profile conformance without adding
/// repository-specific exceptions to the universal filing engine.
///
/// # Errors
///
/// Returns [`FindingError`] if a normalized Standard finding cannot be constructed.
pub fn evaluate_module_grammar_with_profiles(
    observed_paths: &[String],
    standard_edition: &str,
    profiles: &FilingSystemProfiles,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let model = analyze_project_filing_system(observed_paths, profiles);
    findings_from_model(&model, standard_edition)
}

/// Converts one canonical Project Filing System model into Standard findings.
///
/// # Errors
///
/// Returns [`FindingError`] if normalized finding evidence cannot be constructed.
pub fn findings_from_model(
    model: &ProjectFilingModel,
    standard_edition: &str,
) -> Result<Vec<CanonicalFinding>, FindingError> {
    let definition = RuleFindingDefinition::new(
        REPO_MODULE_RULE_ID,
        1,
        FindingCategory::Repository,
        REMEDIATION,
    )?;
    let evaluator = EvaluatorProvenance::new(
        "fortress-core/project-filing-system",
        env!("CARGO_PKG_VERSION"),
    )?;
    let mut findings = Vec::new();
    for violation in model.violations() {
        findings.push(CanonicalFinding::failure(
            definition.clone(),
            FindingOccurrence::new(
                Vec::new(),
                FindingLocation::at_path(violation.path())?,
                violation.message(),
            )?,
            evaluator.clone(),
            standard_edition,
            None,
        )?);
    }
    findings.sort();
    findings.dedup();
    Ok(findings)
}

pub use crate::filing::is_lexical_name;
