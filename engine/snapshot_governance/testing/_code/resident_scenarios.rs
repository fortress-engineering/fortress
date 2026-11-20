//! Deterministic mutations and independent mechanism assertions for registered comparisons.
use super::resident_campaign::Scenario;
use super::{ACTUAL_PATH, CandidateSpec, Result, Warm, failure, require_cold_owner_work};
use fortress_core::control_layout::{ControlLayout, ControlRole};
use fortress_core::program_semantics::ExecutableSymbol;
use fortress_core::semantic_analysis::FunctionEffect;
use fortress_core::session::{Generation, SessionDisposition};
use std::sync::OnceLock;

const FIXTURE_CODE: &str = "src/unit_000.rs";
static LAYOUT: OnceLock<ControlLayout> = OnceLock::new();

fn at(
    path: &'static str,
    needle: &'static str,
    replacement: &'static str,
) -> CandidateSpec<'static> {
    CandidateSpec {
        path,
        needle,
        replacement,
        candidate_id: "measured",
    }
}

pub(super) fn operation(scenario: Scenario) -> Option<CandidateSpec<'static>> {
    use Scenario::{
        AuthorityInvalidation, BaselineAfterCandidates, BaselineRefresh, CalleeBody,
        DependencyInput, FilesystemEffect, InterproceduralDependency, LocalBody, PathPredicateBody,
        ReadBudgetBody, Signature, TransitiveInvalidation, UnavailablePreparation,
        UnresolvedRelationship,
    };
    match scenario {
        BaselineRefresh | BaselineAfterCandidates => None,
        PathPredicateBody => Some(at(ACTUAL_PATH, "!value.is_empty()", "value.len() > 1")),
        ReadBudgetBody => Some(at(
            ACTUAL_PATH,
            "if observed > maximum {\n        return Err(ObservationError::ResourceLimit {\n            resource: \"source_bytes\",",
            "if observed >= maximum {\n        return Err(ObservationError::ResourceLimit {\n            resource: \"source_bytes\",",
        )),
        InterproceduralDependency => Some(at(
            ACTUAL_PATH,
            "relative_path_bytes(root, directory)?",
            "relative_path(root, directory)?.len()",
        )),
        AuthorityInvalidation => Some(at(
            LAYOUT
                .get_or_init(ControlLayout::standard)
                .role_path(ControlRole::ProjectConfiguration)
                .expect("registered project configuration role"),
            "\"assurance_profiles\": []",
            concat!(
                "\"assurance_profiles\": [{\"id\":\"ASSURE-SEMANTIC-EVALUABILITY\",",
                "\"version\":\"1.0.0\",\"digest\":",
                "\"sha256:590aa518f3ea324d396877362e6a68c98febf297990810e46523729aa35786c8\"}]",
            ),
        )),
        LocalBody => Some(at(
            FIXTURE_CODE,
            "f0000() -> u32 { 1 }",
            "f0000() -> u32 { 11 }",
        )),
        UnavailablePreparation => Some(at(
            FIXTURE_CODE,
            "f0005() -> u32 { 1 }",
            "f0005() -> u32 { 51 }",
        )),
        Signature => Some(at(
            FIXTURE_CODE,
            "f0003() -> u32 { 1 }",
            "f0003() -> u64 { 1 }",
        )),
        DependencyInput => Some(at(
            "Cargo.toml",
            "edition = \"2024\"",
            "edition = \"2024\"\n\n[dependencies]\nserde = \"1\"",
        )),
        CalleeBody => Some(at(
            FIXTURE_CODE,
            "f0001() -> u32 { f0002(); 1 }",
            "f0001() -> u32 { f0002(); 2 }",
        )),
        FilesystemEffect => Some(at(
            FIXTURE_CODE,
            "f0000() -> u32 { f0001(); 1 }",
            "f0000() -> u32 { f0001(); let _ = std::fs::read(\"effect.txt\"); 1 }",
        )),
        TransitiveInvalidation => Some(at(
            FIXTURE_CODE,
            "f0014() -> u32 { f0015(); 1 }",
            "f0014() -> u32 { f0015(); let _ = std::fs::write(\"transitive.txt\", b\"fixture\"); 1 }",
        )),
        UnresolvedRelationship => Some(at(
            FIXTURE_CODE,
            "f0000() -> u32 { f0001(); 1 }",
            "f0000() -> u32 { f9999(); 1 }",
        )),
    }
}

fn symbol<'a>(generation: &'a Generation, path: &str, name: &str) -> Result<&'a ExecutableSymbol> {
    let mut matches = generation.psm().symbols().iter().filter(|symbol| {
        symbol.source_path() == path && symbol.qualified_name().rsplit("::").next() == Some(name)
    });
    let first = matches
        .next()
        .ok_or_else(|| failure(format!("missing symbol {name} in {path}")))?;
    assert_case(matches.next().is_none(), "unique observed symbol")?;
    Ok(first)
}

fn assert_case(value: bool, expectation: &'static str) -> Result<&'static str> {
    if !value {
        return Err(failure(format!(
            "registered scenario did not exercise {expectation}"
        )));
    }
    Ok(expectation)
}

fn edge(generation: &Generation, path: &str, origin: &str, target: &str) -> Result<bool> {
    let from = symbol(generation, path, origin)?.id();
    let to = symbol(generation, path, target)?.id();
    Ok(generation
        .psm()
        .calls()
        .iter()
        .any(|call| call.caller() == from && call.callee() == Some(to)))
}

fn effect(
    generation: &Generation,
    name: &str,
    wanted: FunctionEffect,
    direct: bool,
) -> Result<bool> {
    let id = symbol(generation, FIXTURE_CODE, name)?.id();
    Ok(generation
        .state_effect()
        .model()
        .summaries()
        .iter()
        .any(|summary| {
            let effects = if direct {
                summary.direct_effects()
            } else {
                summary.transitive_effects()
            };
            summary.symbol() == id && effects.contains(&wanted)
        }))
}

pub(super) fn verify(scenario: Scenario, base: &Generation, warm: &Warm) -> Result<&'static str> {
    use Scenario::{
        AuthorityInvalidation, BaselineAfterCandidates, BaselineRefresh, CalleeBody,
        DependencyInput, FilesystemEffect, InterproceduralDependency, LocalBody, PathPredicateBody,
        ReadBudgetBody, Signature, TransitiveInvalidation, UnavailablePreparation,
        UnresolvedRelationship,
    };
    let result = &warm.generation;
    let metrics = &warm.metrics;
    let program = &metrics.work.program;
    let full = metrics.disposition == SessionDisposition::FullReevaluationRequired;
    if operation(scenario).is_some() {
        assert_case(
            base.input_revision() != result.input_revision(),
            "a distinct source revision",
        )?;
    }
    match scenario {
        BaselineRefresh | BaselineAfterCandidates => assert_case(
            base.input_revision() == result.input_revision()
                && base.canonical_artifacts() == result.canonical_artifacts(),
            "unchanged exact source and canonical result",
        ),
        PathPredicateBody | ReadBudgetBody => {
            let name = if scenario == PathPredicateBody {
                "is_canonical_relative_path"
            } else {
                "admit_source_bytes"
            };
            assert_case(
                symbol(base, ACTUAL_PATH, name)?.id() == symbol(result, ACTUAL_PATH, name)?.id()
                    && program.analyzed_bodies > 0,
                "changed executable body with unchanged signature",
            )
        }
        InterproceduralDependency => assert_case(
            edge(
                base,
                ACTUAL_PATH,
                "bounded_directory_entries",
                "relative_path_bytes",
            )? && !edge(
                result,
                ACTUAL_PATH,
                "bounded_directory_entries",
                "relative_path_bytes",
            )? && edge(
                result,
                ACTUAL_PATH,
                "bounded_directory_entries",
                "relative_path",
            )? && program.rebuilt_callers > 0,
            "replacement of a resolved dependency edge and caller rebuild",
        ),
        AuthorityInvalidation => {
            require_cold_owner_work(&metrics.work)?;
            assert_case(
                full && base.authority_digest() != result.authority_digest(),
                "authority change with conservative full reconstruction",
            )
        }
        LocalBody => assert_case(
            symbol(base, FIXTURE_CODE, "f0000")?.id()
                == symbol(result, FIXTURE_CODE, "f0000")?.id()
                && program.analyzed_bodies > 0
                && program.reused_bodies > 0,
            "bounded body rebuild and unaffected body reuse",
        ),
        Signature => assert_case(
            symbol(base, FIXTURE_CODE, "f0003")?.id()
                != symbol(result, FIXTURE_CODE, "f0003")?.id()
                && program.rebuilt_declaration_files > 0,
            "new signature identity and declaration rebuild",
        ),
        DependencyInput => {
            require_cold_owner_work(&metrics.work)?;
            assert_case(
                full && base.context_digest() != result.context_digest(),
                "dependency context change with no owner reuse",
            )
        }
        UnavailablePreparation => {
            require_cold_owner_work(&metrics.work)?;
            assert_case(
                full && program.parsed_files > 0 && program.reused_parse_files == 0,
                "no-preparation fallback with complete source reparsing",
            )
        }
        CalleeBody | FilesystemEffect | TransitiveInvalidation | UnresolvedRelationship => {
            verify_graph(scenario, base, warm)
        }
    }
}

fn verify_graph(scenario: Scenario, base: &Generation, warm: &Warm) -> Result<&'static str> {
    let result = &warm.generation;
    let program = &warm.metrics.work.program;
    match scenario {
        Scenario::CalleeBody => assert_case(
            edge(base, FIXTURE_CODE, "f0000", "f0001")?
                && edge(result, FIXTURE_CODE, "f0000", "f0001")?
                && symbol(base, FIXTURE_CODE, "f0001")?.id()
                    == symbol(result, FIXTURE_CODE, "f0001")?.id()
                && program.analyzed_bodies > 0
                && program.reused_bodies > 0,
            "changed callee body under a retained resolved caller edge",
        ),
        Scenario::FilesystemEffect => assert_case(
            !effect(base, "f0000", FunctionEffect::FilesystemRead, true)?
                && effect(result, "f0000", FunctionEffect::FilesystemRead, true)?,
            "new directly modeled filesystem read",
        ),
        Scenario::TransitiveInvalidation => assert_case(
            !effect(base, "f0000", FunctionEffect::FilesystemWrite, false)?
                && effect(result, "f0014", FunctionEffect::FilesystemWrite, true)?
                && effect(result, "f0000", FunctionEffect::FilesystemWrite, false)?
                && !effect(result, "f0000", FunctionEffect::FilesystemWrite, true)?
                && warm.metrics.work.state_effect.rebuilt_closure_rounds > 0,
            "modeled write reaches an unchanged transitive caller through rebuilt closure",
        ),
        Scenario::UnresolvedRelationship => {
            let caller = symbol(result, FIXTURE_CODE, "f0000")?.id();
            assert_case(
                edge(base, FIXTURE_CODE, "f0000", "f0001")?
                    && !edge(result, FIXTURE_CODE, "f0000", "f0001")?
                    && result.psm().calls().iter().any(|call| {
                        call.caller() == caller
                            && call.callee().is_none()
                            && call.reason().is_some()
                    })
                    && program.recomputed_components > 0,
                "removed edge, explicit unresolved call reason, and changed component",
            )
        }
        _ => Err(failure("non-graph scenario in graph verification")),
    }
}
