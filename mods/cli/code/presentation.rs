//! Human projections of canonical Fortress results.
//!
//! Presentation never re-evaluates authority, policy, coverage, lifecycle, or
//! enforcement. It names and groups canonical evidence so the terminal cannot
//! imply a cleaner result than the machine-readable model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use fortress_core::audit::ModuleInspection;
use fortress_core::program_semantics::ExecutionProvenance;
use fortress_core::semantic_conformance::{
    BlockingEligibility, ModuleEffectObservation, ModuleSemanticConformance, PolicyDisposition,
    PolicyTargetKind, SemanticConformanceEvaluation, SemanticConformanceState,
};
use fortress_core::state_effect_analysis::EffectEvidenceKind;

pub(crate) fn render_module_inspection(inspection: &ModuleInspection) -> String {
    let mut output = format!(
        "Fortress Module Inspection\nProject authority: {}\n",
        inspection.project_authority_state()
    );
    let governance_usable = inspection.is_valid() && inspection.has_declared_authority();
    if inspection.is_valid() {
        let _ = writeln!(
            output,
            "Module governance: {}",
            if inspection.has_declared_authority() {
                "VALID"
            } else {
                "NOT_EVALUABLE"
            }
        );
    } else {
        output.push_str("Module governance: INVALID\n");
    }
    if let Some(detail) = inspection.governance_detail().or_else(|| {
        inspection
            .ownership_diagnostics()
            .first()
            .map(fortress_core::implementation_observation::SourceOwnershipDiagnostic::detail)
    }) {
        output.push_str("Reason:\n  ");
        output.push_str(detail);
        output.push('\n');
    }
    if !governance_usable {
        output.push_str(
            "Governed Module conclusions are unavailable until authored authority and resolved ownership are valid.\nMechanical repository observation remains available below.\n",
        );
    }
    let module_heading = if governance_usable {
        "Declared Modules"
    } else {
        "Observed/partially loaded Module contracts"
    };
    let _ = writeln!(output, "\n{module_heading}: {}", inspection.modules().len());
    for module in inspection.modules() {
        let _ = writeln!(
            output,
            "  {} [{}] contract={} bindings={} sources={}",
            module.module(),
            module.authority(),
            module.contract(),
            module.bindings().len(),
            module.observed_sources()
        );
    }
    let _ = writeln!(
        output,
        "\nMechanical analysis territories (not authored Modules): {}",
        inspection.analysis_territories().len()
    );
    for territory in inspection.analysis_territories() {
        let _ = writeln!(
            output,
            "  {} path={} sources={}",
            territory.territory(),
            territory.path(),
            territory.observed_sources()
        );
    }
    output.push_str("\nOwnership/binding diagnostics:\n");
    if inspection.ownership_diagnostics().is_empty() {
        output.push_str("  None\n");
    } else {
        for diagnostic in inspection.ownership_diagnostics() {
            let _ = writeln!(
                output,
                "  INVALID {} path={} modules={} {}",
                diagnostic.code(),
                diagnostic.source_path(),
                diagnostic.modules().join(","),
                diagnostic.detail()
            );
        }
    }
    output
}

pub(crate) fn render_semantic_conformance(
    evaluation: &SemanticConformanceEvaluation,
    modules: &[&ModuleSemanticConformance],
) -> String {
    let mut output = format!(
        "Fortress Semantic Conformance\nCommand result: {}\nRaw semantic findings (repository-wide): {}\nBlock-supported findings (repository-wide): {}\nAdvisory findings (repository-wide): {}\nNot-evaluable findings (repository-wide): {}\nRendered Modules: {}\n",
        if evaluation.is_success() {
            "SUCCESS"
        } else {
            "NON_SUCCESS"
        },
        evaluation.findings().len(),
        evaluation.model().summary().blocking_findings(),
        evaluation.model().summary().advisory_findings(),
        evaluation.coverage_findings().len(),
        modules.len(),
    );
    if !evaluation.is_success() {
        output.push_str(
            "Reason: supported semantic violations or explicitly unevaluable governed claims remain.\n",
        );
    }
    for module in modules {
        render_semantic_module(&mut output, evaluation, module);
    }
    output
}

#[allow(clippy::too_many_lines)]
fn render_semantic_module(
    output: &mut String,
    evaluation: &SemanticConformanceEvaluation,
    module: &ModuleSemanticConformance,
) {
    let _ = write!(
        output,
        "\nModule {}\n  Policy authority: {}\n  Raw semantic conformance: {}\n  Contract: {}\n  Rule: {}\n  Semantic coverage: {}/{} governed source files ({})\n",
        module.module(),
        module.policy_state(),
        conformance_label(module.state()),
        module.contract_path(),
        fortress_core::semantic_conformance::ARCH_SEMANTIC_RULE_ID,
        module.coverage().analysed_source_files(),
        module.coverage().governed_source_files(),
        module.coverage().ratio().unwrap_or("NOT_APPLICABLE"),
    );
    if module.coverage().governed_source_files() == 0 {
        output.push_str("  Coverage status: NOT_APPLICABLE — no governed source subject exists.\n");
    }
    render_module_coverage_reasons(output, module);

    let authorizations = module
        .conclusions()
        .iter()
        .filter(|conclusion| conclusion.disposition() == PolicyDisposition::Allow)
        .collect::<Vec<_>>();
    output.push_str("  Authorizations:\n");
    if authorizations.is_empty() {
        output.push_str("    None\n");
    } else {
        for authorization in authorizations {
            let _ = writeln!(
                output,
                "    {} {}: {} (observed supported uses: {}; coverage: {})",
                target_kind_label(authorization.target_kind()),
                authorization.target(),
                authorization
                    .authorization()
                    .expect("ALLOW is authorization")
                    .as_str(),
                authorization.matching_observation_count(),
                authorization.coverage().ratio().unwrap_or("NOT_APPLICABLE"),
            );
        }
    }

    let claims = module
        .conclusions()
        .iter()
        .filter(|conclusion| conclusion.disposition() == PolicyDisposition::Deny)
        .collect::<Vec<_>>();
    output.push_str("  Conformance claims:\n");
    if claims.is_empty() {
        output.push_str("    None — authored permissions alone are not conformance claims.\n");
    } else {
        for claim in claims {
            let _ = writeln!(
                output,
                "    {} {} DENY: {} / {} (matching observations: {}; coverage: {})",
                target_kind_label(claim.target_kind()),
                claim.target(),
                conformance_label(claim.conformance().expect("DENY is evaluative")),
                eligibility_label(claim.blocking_eligibility().expect("DENY has eligibility")),
                claim.matching_observation_count(),
                claim.coverage().ratio().unwrap_or("NOT_APPLICABLE"),
            );
            for reason in claim.coverage_reasons() {
                let _ = writeln!(output, "      Coverage reason: {reason}");
                if reason == fortress_core::semantic_conformance::NO_SEMANTIC_COVERAGE {
                    let _ = writeln!(
                        output,
                        "      Fortress analyzed none of this Module's {} governed source file(s).",
                        claim.coverage().governed_source_files()
                    );
                }
            }
            for reason in claim.enforcement_reasons() {
                let _ = writeln!(output, "      Enforcement reason: {reason}");
                if reason == fortress_core::semantic_conformance::TEST_ONLY_EVIDENCE {
                    output.push_str(
                        "      All currently supported violating evidence originates in Rust test-only execution.\n",
                    );
                } else if reason
                    == fortress_core::semantic_conformance::UNKNOWN_EXECUTION_PROVENANCE
                {
                    output.push_str(
                        "      Current violating evidence does not establish production-capable execution.\n",
                    );
                }
            }
            let provenance = claim.evidence_provenance();
            if claim.matching_observation_count() > 0 {
                let _ = writeln!(
                    output,
                    "      Evidence provenance: production-capable {}, test-only {}, unknown {}",
                    provenance.production_capable_observations(),
                    provenance.test_only_observations(),
                    provenance.unknown_observations(),
                );
            }
        }
    }

    let governed = module
        .observations()
        .iter()
        .filter(|observation| observation.policy_disposition() == Some(PolicyDisposition::Deny))
        .collect::<Vec<_>>();
    let sites = group_offending_sites(&governed);
    if !sites.is_empty() {
        let _ = write!(
            output,
            "  Semantic violation evidence:\n    Distinct offending sites: {}\n    Evidence paths: {}\n",
            sites.len(),
            governed.len(),
        );
        for (index, site) in sites.values().enumerate() {
            render_offending_site(output, evaluation, index + 1, site);
        }
    }
    if module.state() == SemanticConformanceState::Fail {
        output.push_str(
            "  Remediation: remove or isolate the forbidden reachable operation, or explicitly revise the Module Contract policy after architectural review.\n",
        );
    }
    if module.state() == SemanticConformanceState::Unknown {
        output.push_str(
            "  Remediation: resolve the claim-relevant semantic gap; missing authority is not conformance.\n",
        );
    }
}

fn render_module_coverage_reasons(output: &mut String, module: &ModuleSemanticConformance) {
    const HUMAN_REASON_LIMIT: usize = 5;
    let reasons = module.coverage_reasons();
    if reasons.is_empty() {
        return;
    }
    let _ = writeln!(output, "  Semantic coverage limitations: {}", reasons.len());
    for reason in reasons.iter().take(HUMAN_REASON_LIMIT) {
        let _ = writeln!(output, "    - {reason}");
        if reason == fortress_core::semantic_conformance::NO_SEMANTIC_COVERAGE {
            let _ = writeln!(
                output,
                "      Fortress analyzed none of this Module's {} governed source file(s).",
                module.coverage().governed_source_files()
            );
        }
    }
    if reasons.len() > HUMAN_REASON_LIMIT {
        let _ = writeln!(
            output,
            "    - ... {} additional limitation(s); use --format json for the complete canonical list.",
            reasons.len() - HUMAN_REASON_LIMIT
        );
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OffendingSiteKey {
    target_kind: String,
    target: String,
    source_symbol: String,
    operation: String,
    path: String,
    line: u32,
    column: u32,
}

#[derive(Clone, Debug)]
struct OffendingSite {
    key: OffendingSiteKey,
    effects: BTreeSet<String>,
    capabilities: BTreeSet<String>,
    authorities: BTreeSet<String>,
    entry_provenance: BTreeMap<ExecutionProvenance, usize>,
    source_provenance: BTreeMap<ExecutionProvenance, usize>,
    direct: bool,
    call_chains: BTreeSet<Vec<String>>,
}

fn group_offending_sites(
    observations: &[&ModuleEffectObservation],
) -> BTreeMap<OffendingSiteKey, OffendingSite> {
    let mut sites = BTreeMap::new();
    for observation in observations {
        let key = OffendingSiteKey {
            target_kind: observation.policy_target_kind().map_or_else(
                || "UNSPECIFIED".into(),
                |kind| target_kind_label(kind).into(),
            ),
            target: observation.policy_target().unwrap_or("UNSPECIFIED").into(),
            source_symbol: observation.source_symbol().into(),
            operation: observation.operation().into(),
            path: observation.path().into(),
            line: observation.line(),
            column: observation.column(),
        };
        let site = sites.entry(key.clone()).or_insert_with(|| OffendingSite {
            key,
            effects: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            authorities: BTreeSet::new(),
            entry_provenance: BTreeMap::new(),
            source_provenance: BTreeMap::new(),
            direct: false,
            call_chains: BTreeSet::new(),
        });
        site.effects.insert(observation.effect().stable_id().into());
        if let Some(capability) = observation.capability() {
            site.capabilities.insert(capability.stable_id().into());
        }
        site.authorities.insert(observation.authority().into());
        *site
            .entry_provenance
            .entry(observation.entry_execution_provenance())
            .or_default() += 1;
        *site
            .source_provenance
            .entry(observation.source_execution_provenance())
            .or_default() += 1;
        site.direct |= observation.evidence_kind() == EffectEvidenceKind::Direct;
        site.call_chains.insert(observation.call_chain().to_vec());
    }
    sites
}

fn render_offending_site(
    output: &mut String,
    evaluation: &SemanticConformanceEvaluation,
    index: usize,
    site: &OffendingSite,
) {
    let _ = write!(
        output,
        "\n    {index}. Operation: {}\n       Policy: {} {} DENY\n       Effect(s): {}\n       Capability consequence(s): {}\n       Site: {}:{}:{}\n       Origin: {}\n       Entry-path provenance: {}\n       Direct-origin provenance: {}\n       Direct operation evidence: {}\n       Classification authority: {}\n       Reachable through ({} path{}):\n",
        site.key.operation,
        site.key.target_kind,
        site.key.target,
        site.effects.iter().cloned().collect::<Vec<_>>().join(", "),
        if site.capabilities.is_empty() {
            "none".into()
        } else {
            site.capabilities
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
        site.key.path,
        site.key.line,
        site.key.column,
        display_symbol(evaluation, &site.key.source_symbol),
        render_provenance_counts(&site.entry_provenance),
        render_provenance_counts(&site.source_provenance),
        if site.direct { "yes" } else { "no" },
        site.authorities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        site.call_chains.len(),
        if site.call_chains.len() == 1 { "" } else { "s" },
    );
    for chain in &site.call_chains {
        let mut labels = chain
            .iter()
            .map(|symbol| display_symbol(evaluation, symbol))
            .collect::<Vec<_>>();
        labels.push(site.key.operation.clone());
        let _ = writeln!(output, "       - {}", labels.join(" -> "));
    }
}

fn render_provenance_counts(counts: &BTreeMap<ExecutionProvenance, usize>) -> String {
    counts
        .iter()
        .map(|(provenance, count)| format!("{} {count}", execution_provenance_label(*provenance)))
        .collect::<Vec<_>>()
        .join(", ")
}

const fn execution_provenance_label(provenance: ExecutionProvenance) -> &'static str {
    match provenance {
        ExecutionProvenance::ProductionCapable => "PRODUCTION_CAPABLE",
        ExecutionProvenance::TestOnly => "TEST_ONLY",
        ExecutionProvenance::Unknown => "UNKNOWN",
    }
}

fn display_symbol(evaluation: &SemanticConformanceEvaluation, stable_id: &str) -> String {
    evaluation
        .symbol_display_name(stable_id)
        .map_or_else(|| stable_id.to_owned(), str::to_owned)
}

const fn target_kind_label(kind: PolicyTargetKind) -> &'static str {
    match kind {
        PolicyTargetKind::Capability => "CAPABILITY",
        PolicyTargetKind::Effect => "EFFECT",
    }
}

const fn conformance_label(state: SemanticConformanceState) -> &'static str {
    match state {
        SemanticConformanceState::Pass => "PASS",
        SemanticConformanceState::Fail => "FAIL",
        SemanticConformanceState::Unknown => "UNKNOWN",
        SemanticConformanceState::NotApplicable => "NOT_APPLICABLE",
    }
}

const fn eligibility_label(eligibility: BlockingEligibility) -> &'static str {
    match eligibility {
        BlockingEligibility::BlockSupported => "BLOCK_SUPPORTED",
        BlockingEligibility::AdvisoryOnly => "ADVISORY_ONLY",
        BlockingEligibility::NotEvaluable => "NOT_EVALUABLE",
    }
}
