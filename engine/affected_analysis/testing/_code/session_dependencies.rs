//! Session dependency coverage and conservative invalidation controls.

use std::collections::BTreeSet;

use fortress_core::affected_analysis::{
    AffectedInput, AffectedSnapshot, AffectedUnit, AffectedUnitKind, SessionDependencyIndex,
    SessionInputDescriptor, SessionInputRole, SessionInvalidationStatus, sha256,
};
use fortress_core::implementation_observation::{
    ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
};
use fortress_core::program_semantics::{
    PreparedProgramSemanticModel, ProgramDependencyKind, ProgramDependencyRead,
    ProgramDependencyResult, ProgramSemanticInput, prepare_program_semantics,
};

const SOURCE: &str = "sample/_code/lib.rs";
const MANIFEST_PATH: &str = "sample/_data/Cargo.toml";
const MANIFEST: &str =
    "[package]\nname='sample'\nversion='0.1.0'\nedition='2024'\n[lib]\npath='../_code/lib.rs'\n";

struct Fixture {
    prepared: PreparedProgramSemanticModel,
    snapshot: AffectedSnapshot,
    descriptors: Vec<SessionInputDescriptor>,
}

fn fixture(source: &str) -> Fixture {
    let files = [(MANIFEST_PATH, MANIFEST), (SOURCE, source)];
    let input = ProgramSemanticInput::new(
        "PF-DEPENDENCY-FIXTURE",
        ImplementationObservationInput::new(
            "sha256:fixture",
            files
                .iter()
                .map(|(path, bytes)| SnapshotBoundFile::from_bytes(*path, bytes.as_bytes()))
                .collect(),
            vec![
                ModuleTerritory::new("PF-DEPENDENCY-FIXTURE", ""),
                ModuleTerritory::new("AF-SAMPLE-0001", "sample"),
            ],
        ),
        [],
        [],
    );
    let prepared = prepare_program_semantics(&input, None).expect("owner preparation");
    let inputs = files
        .iter()
        .map(|(path, bytes)| {
            AffectedInput::new(*path, sha256(bytes.as_bytes()), bytes.len() as u64).unwrap()
        })
        .collect::<Vec<_>>();
    let mut units = inputs
        .iter()
        .flat_map(|input| {
            [
                AffectedUnit::new(
                    format!("authority:{}", input.path()),
                    AffectedUnitKind::AuthorityInput,
                    input.digest(),
                    [] as [&str; 0],
                )
                .unwrap(),
                AffectedUnit::new(
                    format!("source:{}", input.path()),
                    AffectedUnitKind::SourceArtifact,
                    input.digest(),
                    [format!("authority:{}", input.path())],
                )
                .unwrap(),
            ]
        })
        .collect::<Vec<_>>();
    units.push(
        AffectedUnit::new(
            "evaluation:input-key",
            AffectedUnitKind::Projection,
            sha256(b"context"),
            [] as [&str; 0],
        )
        .unwrap(),
    );
    for symbol in prepared.model.symbols() {
        units.push(
            AffectedUnit::new(
                format!("symbol:{}", symbol.id()),
                AffectedUnitKind::Symbol,
                sha256(&serde_json::to_vec(&[symbol]).unwrap()),
                [format!("source:{}", symbol.source_path())],
            )
            .unwrap(),
        );
    }
    for call in prepared.model.calls() {
        let mut dependencies = vec![format!("symbol:{}", call.caller())];
        if let Some(callee) = call.callee() {
            dependencies.push(format!("symbol:{callee}"));
        }
        units.push(
            AffectedUnit::new(
                format!("call:{}", call.id()),
                AffectedUnitKind::CallRelationship,
                sha256(&serde_json::to_vec(&[call]).unwrap()),
                dependencies,
            )
            .unwrap(),
        );
    }
    let snapshot = AffectedSnapshot::new(sha256(source.as_bytes()), inputs, units).unwrap();
    let descriptors = fixture_descriptors(&snapshot);
    Fixture {
        prepared,
        snapshot,
        descriptors,
    }
}

fn fixture_descriptors(snapshot: &AffectedSnapshot) -> Vec<SessionInputDescriptor> {
    snapshot
        .inputs()
        .iter()
        .map(|input| {
            SessionInputDescriptor::new(
                input.path(),
                input.digest(),
                if input.path() == MANIFEST_PATH {
                    SessionInputRole::Authority
                } else {
                    SessionInputRole::Source
                },
            )
            .unwrap()
        })
        .collect()
}

fn index(fixture: &Fixture) -> SessionDependencyIndex {
    index_with(
        fixture,
        &fixture.prepared.dependencies,
        &fixture.descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    )
}

fn index_with(
    fixture: &Fixture,
    reads: &[ProgramDependencyRead],
    descriptors: &[SessionInputDescriptor],
    selected: &BTreeSet<String>,
    authority: &str,
) -> SessionDependencyIndex {
    SessionDependencyIndex::new(
        &fixture.snapshot,
        &fixture.prepared.model,
        reads,
        authority,
        selected,
        descriptors,
    )
    .expect("dependency index")
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-001`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn complete_owner_queries_bind_real_inputs_and_units() {
    let fixture = fixture("fn stable() {} fn run() { stable(); }");
    let index = index(&fixture);
    assert!(index.coverage_complete());
    assert_eq!(
        index.invalidate(&index).status(),
        SessionInvalidationStatus::Unchanged
    );
    let stable = fixture
        .prepared
        .model
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::stable"))
        .unwrap();
    assert!(!index.provider_dependents(stable.id()).is_empty());
    let query = fixture
        .prepared
        .dependencies
        .iter()
        .find(|read| {
            read.kind == ProgramDependencyKind::Name
                && read.query.contains("stable")
                && matches!(&read.result, ProgramDependencyResult::Resolved(_))
        })
        .unwrap();
    assert!(!index.query_dependents(query.kind, &query.query).is_empty());
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-002`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn missing_name_buckets_survive_and_new_binders_require_full_reconstruction() {
    let before = fixture("fn run() { absent(); }");
    let before_index = index(&before);
    let miss = before
        .prepared
        .dependencies
        .iter()
        .find(|read| {
            read.kind == ProgramDependencyKind::Name
                && read.query.contains("absent")
                && read.result == ProgramDependencyResult::Unresolved
        })
        .unwrap();
    assert!(
        !before_index
            .query_dependents(miss.kind, &miss.query)
            .is_empty()
    );
    let after = fixture("fn run() { absent(); } fn absent() {}");
    let change = before_index.invalidate(&index(&after));
    assert_eq!(
        change.status(),
        SessionInvalidationStatus::FullReevaluationRequired
    );
    assert!(
        change
            .reasons()
            .iter()
            .any(|reason| reason.contains("declaration"))
    );
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-003`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn body_input_change_marks_current_reverse_closure_without_authorizing_owner_reuse() {
    let before = fixture("fn run() { let value = 1u8; stable(); } fn stable() {}");
    let after = fixture("fn run() { let value = 2u8; stable(); } fn stable() {}");
    let change = index(&before).invalidate(&index(&after));
    assert_eq!(change.status(), SessionInvalidationStatus::Selective);
    assert_eq!(change.changed_inputs(), &[SOURCE.to_owned()]);
    let caller = after
        .prepared
        .model
        .symbols()
        .iter()
        .find(|symbol| symbol.qualified_name().ends_with("::run"))
        .unwrap();
    assert!(
        change
            .affected_units()
            .contains(&format!("symbol:{}", caller.id()))
    );
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-004`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn control_authority_and_retained_availability_have_separate_invalidation() {
    let fixture = fixture("fn run() {}");
    let history = format!(
        "__fortress/evidence/generations/{}/manifest.json",
        "a".repeat(64)
    );
    let mut old_descriptors = fixture.descriptors.clone();
    old_descriptors.push(
        SessionInputDescriptor::new(&history, sha256(b"old"), SessionInputRole::Availability)
            .unwrap(),
    );
    let mut new_descriptors = fixture.descriptors.clone();
    new_descriptors.push(
        SessionInputDescriptor::new(&history, sha256(b"new"), SessionInputRole::Availability)
            .unwrap(),
    );
    let old = index_with(
        &fixture,
        &fixture.prepared.dependencies,
        &old_descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    let current = index_with(
        &fixture,
        &fixture.prepared.dependencies,
        &new_descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    let availability = old.invalidate(&current);
    assert_eq!(availability.status(), SessionInvalidationStatus::Unchanged);
    assert_eq!(
        availability.availability_changes(),
        std::slice::from_ref(&history)
    );
    let authority = index_with(
        &fixture,
        &fixture.prepared.dependencies,
        &new_descriptors,
        &BTreeSet::new(),
        &sha256(b"new-authority"),
    );
    assert_eq!(
        old.invalidate(&authority).status(),
        SessionInvalidationStatus::FullReevaluationRequired
    );
    let selected = BTreeSet::from([history]);
    let conflict = index_with(
        &fixture,
        &fixture.prepared.dependencies,
        &new_descriptors,
        &selected,
        &sha256(b"authority"),
    );
    assert!(!conflict.coverage_complete());
    assert_eq!(
        old.invalidate(&conflict).status(),
        SessionInvalidationStatus::FullReevaluationRequired
    );
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-005`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn incomplete_or_unsupported_descriptor_coverage_requires_full_reconstruction() {
    let fixture = fixture("fn run() { missing(); }");
    let mut reads = fixture.prepared.dependencies.clone();
    reads.retain(|read| read.kind != ProgramDependencyKind::Context);
    let incomplete = index_with(
        &fixture,
        &reads,
        &fixture.descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    assert!(!incomplete.coverage_complete());
    assert_eq!(
        incomplete.invalidate(&incomplete).status(),
        SessionInvalidationStatus::FullReevaluationRequired
    );
    let mut unsupported = fixture.prepared.dependencies.clone();
    unsupported.push(ProgramDependencyRead {
        source_path: SOURCE.into(),
        caller: fixture
            .prepared
            .model
            .symbols()
            .first()
            .map(|symbol| symbol.id().to_owned()),
        kind: ProgramDependencyKind::Name,
        query: "unmapped_query".into(),
        result: ProgramDependencyResult::Unsupported,
    });
    let incomplete = index_with(
        &fixture,
        &unsupported,
        &fixture.descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    assert!(!incomplete.coverage_complete());
    assert_eq!(
        incomplete.invalidate(&incomplete).status(),
        SessionInvalidationStatus::FullReevaluationRequired
    );
    check_exact_read_scopes(&fixture);
}

fn check_exact_read_scopes(fixture: &Fixture) {
    let original = fixture
        .prepared
        .dependencies
        .iter()
        .find(|read| read.kind == ProgramDependencyKind::Name && read.query.starts_with("call:"))
        .expect("call read")
        .clone();
    for field in 0..5 {
        let mut changed = original.clone();
        match field {
            0 => changed.source_path = MANIFEST_PATH.into(),
            1 => changed.caller = None,
            2 => changed.kind = ProgramDependencyKind::Effect,
            3 => changed.query = "call:unrelated".into(),
            _ => changed.result = ProgramDependencyResult::Unsupported,
        }
        let mut reads = fixture.prepared.dependencies.clone();
        reads.retain(|read| read != &original);
        reads.push(changed);
        let incomplete = index_with(
            fixture,
            &reads,
            &fixture.descriptors,
            &BTreeSet::new(),
            &sha256(b"authority"),
        );
        assert!(!incomplete.coverage_complete());
        assert!(
            incomplete
                .invalidate(&incomplete)
                .reasons()
                .iter()
                .any(|reason| reason.starts_with("call_descriptor_missing:"))
        );
    }
    let mut reads = fixture.prepared.dependencies.clone();
    reads.push(original.clone());
    let mut alternate = original;
    alternate.result = ProgramDependencyResult::Unsupported;
    reads.push(alternate);
    let make_index = |reads: &[ProgramDependencyRead]| {
        index_with(
            fixture,
            reads,
            &fixture.descriptors,
            &BTreeSet::new(),
            &sha256(b"authority"),
        )
    };
    let before = make_index(&reads);
    assert!(before.coverage_complete());
    reads.reverse();
    assert_eq!(
        before.invalidate(&make_index(&reads)).status(),
        SessionInvalidationStatus::Unchanged
    );
}

/// `T-AF-AFFECTED-ANALYSIS-0001-R05-006`
/// Fortress requirement: AF-AFFECTED-ANALYSIS-0001-R05
#[test]
fn source_caller_and_current_unit_identity_must_be_validated() {
    let fixture = fixture("fn run() {}");
    let mut forged = fixture.prepared.dependencies.clone();
    forged.push(ProgramDependencyRead {
        source_path: SOURCE.into(),
        caller: Some("missing-symbol".into()),
        kind: ProgramDependencyKind::Name,
        query: "call:forged".into(),
        result: ProgramDependencyResult::Unresolved,
    });
    let incomplete = index_with(
        &fixture,
        &forged,
        &fixture.descriptors,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    assert!(!incomplete.coverage_complete());
    let mut hidden_source = fixture.descriptors.clone();
    hidden_source.retain(|descriptor| descriptor.path() != SOURCE);
    hidden_source.push(
        SessionInputDescriptor::new(
            SOURCE,
            sha256(b"different-bytes"),
            SessionInputRole::Availability,
        )
        .unwrap(),
    );
    let incomplete = index_with(
        &fixture,
        &fixture.prepared.dependencies,
        &hidden_source,
        &BTreeSet::new(),
        &sha256(b"authority"),
    );
    assert!(!incomplete.coverage_complete());
    assert!(
        SessionInputDescriptor::new("../escape", sha256(b"x"), SessionInputRole::Source).is_err()
    );
    assert!(SessionInputDescriptor::new(SOURCE, "digest", SessionInputRole::Source).is_err());
}
