//! Registered lifecycle assertions over disposable small repositories.
use super::{
    Campaign, Fixture, Result, Retention, Selection, captured_collector, elapsed, failure, options,
};
use fortress_core::observation::ChangeOperation;
use fortress_core::runtime_storage::{RuntimeStorage, StoragePolicy};
use fortress_core::session::{
    Session, SessionDisposition, SessionErrorKind, SessionStage, SourceDelta,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

struct Endurance<'a> {
    retention: &'a mut Retention,
    counts: BTreeMap<String, usize>,
}

impl Endurance<'_> {
    fn checked(&mut self, operation: &str, details: &Value) -> Result<()> {
        self.retention.check_cancellation()?;
        let count = self.counts.entry(operation.into()).or_default();
        *count += 1;
        self.retention.append(&json!({
            "record_kind":"endurance_operation", "operation":operation, "ordinal":count,
            "invariant":"PASS","details":details
        }))
    }
}

fn ensure(valid: bool, invariant: &str) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(failure(format!("lifecycle invariant failed: {invariant}")))
    }
}

const SOURCE: &str = "src/unit_000.rs";

fn compare_lifecycles(
    session: &mut Session,
    fixture: &Fixture,
    run: &mut Endurance<'_>,
) -> Result<()> {
    let baseline = session.acquire_generation()?;
    let original = baseline
        .source_view()
        .bytes(SOURCE)
        .ok_or_else(|| failure("fixture source absent"))?;
    let mutated = std::str::from_utf8(original)?
        .replacen("f0000() -> u32 { 1 }", "f0000() -> u32 { 71 }", 1)
        .into_bytes();
    ensure(mutated != original, "fixture edit has a distinct postimage")?;
    for n in 0..30 {
        run.retention.check_cancellation()?;
        if n < 10 {
            let retained = session.acquire_generation()?;
            fs::write(fixture.root.join(SOURCE), &mutated)?;
            let current = session.refresh(&SourceDelta::default())?;
            ensure(
                current.generation.input_revision() != retained.input_revision(),
                "reader outlives publication",
            )?;
            ensure(
                retained.source_view().bytes(SOURCE) == Some(original)
                    && retained.canonical_artifacts() == baseline.canonical_artifacts(),
                "historical reader bytes",
            )?;
            run.checked("immutable_reader", &json!({"old_revision":retained.input_revision(),"new_revision":current.generation.input_revision()}))?;
            fs::write(fixture.root.join(SOURCE), original)?;
        }
        let current = session.refresh(&SourceDelta::default())?;
        ensure(
            current.generation.canonical_artifacts() == baseline.canonical_artifacts(),
            "exact refresh bytes",
        )?;
        run.checked(
            "resident_refresh",
            &json!({"disposition":format!("{:?}",current.disposition)}),
        )?;
    }
    exercise_candidates(session, run, original, &mutated)
}

fn exercise_candidates(
    session: &mut Session,
    run: &mut Endurance<'_>,
    original: &[u8],
    mutated: &[u8],
) -> Result<()> {
    for _ in 0..20 {
        run.retention.check_cancellation()?;
        let base = session.acquire_generation()?;
        let before = session.resource_usage()?;
        let candidate = session.evaluate_delta(
            "endurance",
            base.input_revision(),
            vec![ChangeOperation::Replace {
                path: SOURCE.into(),
                base_bytes: original.to_vec(),
                candidate_bytes: mutated.to_vec(),
            }],
        )?;
        ensure(
            candidate.generation.source_view().bytes(SOURCE) == Some(mutated)
                && session.acquire_generation()?.input_revision() == base.input_revision(),
            "candidate isolation",
        )?;
        run.checked(
            "candidate_acquire",
            &json!({"revision":candidate.generation.input_revision()}),
        )?;
        session.release_candidate("endurance");
        ensure(
            candidate.generation.source_view().bytes(SOURCE) == Some(mutated),
            "released slot keeps pinned candidate readable",
        )?;
        drop(candidate);
        ensure(
            session.resource_usage()?.1 == before.1,
            "released candidate no longer consumes a generation slot",
        )?;
        run.checked("candidate_release", &json!({"generations":before.1}))?;
    }
    Ok(())
}

fn exercise_preparation(session: &mut Session, run: &mut Endurance<'_>) -> Result<()> {
    let baseline = session.acquire_generation()?;
    for _ in 0..4 {
        run.retention.check_cancellation()?;
        session.evict_preparation()?;
        ensure(
            session.acquire_generation()?.canonical_artifacts() == baseline.canonical_artifacts(),
            "eviction preserves the actual immutable head",
        )?;
        run.checked(
            "evict_preparation",
            &json!({"head":baseline.input_revision()}),
        )?;
        let restored = session.refresh(&SourceDelta::default())?;
        ensure(
            restored.disposition == SessionDisposition::FullReevaluationRequired
                && restored.generation.canonical_artifacts() == baseline.canonical_artifacts(),
            "fallback restores canonical bytes",
        )?;
        let warm = session.refresh(&SourceDelta::default())?;
        ensure(
            warm.disposition == SessionDisposition::InputUnchanged
                && warm.work.program.reused_bodies > 0,
            "restoration makes actual preparation reusable",
        )?;
        run.checked(
            "restore_preparation",
            &json!({"reused_bodies":warm.work.program.reused_bodies}),
        )?;
    }
    for _ in 0..4 {
        run.retention.check_cancellation()?;
        let base = session.acquire_generation()?;
        let control = session.control();
        session.set_progress_observer(move |stage| {
            if stage == SessionStage::ModelsPrepared {
                control.cancel();
            }
        });
        let cancelled = session.refresh(&SourceDelta::default());
        session.set_progress_observer(|_| {});
        ensure(
            matches!(cancelled, Err(ref e) if e.kind() == SessionErrorKind::Cancelled)
                && session.acquire_generation()?.generation_id() == base.generation_id(),
            "cancellation preserves the previous head",
        )?;
        run.checked(
            "cancel_publication",
            &json!({"error":"CANCELLED","head":base.generation_id()}),
        )?;
    }
    Ok(())
}

fn rotate_parser(campaign: Campaign, fixture: &Fixture, run: &mut Endurance<'_>) -> Result<()> {
    let mut calibration = Session::open(&fixture.root, &fixture.storage, options(campaign))?;
    let view = calibration.acquire_generation()?.source_view().clone();
    let first = calibration.evaluate_view_cold(view.clone())?;
    let demand = first.work.parser_admission_bytes_added;
    ensure(demand > 0, "independently observed cold parser admission")?;
    let expected = first.generation.canonical_artifacts().clone();
    drop(first);
    calibration.close()?;
    let mut limited = options(campaign);
    limited.limits.max_parser_bytes = demand
        .checked_add(demand / 2)
        .ok_or_else(|| failure("parser calibration overflow"))?;
    let mut session = Session::open(&fixture.root, &fixture.storage, limited)?;
    for _ in 0..2 {
        run.retention.check_cancellation()?;
        let rotated = session.evaluate_view_cold(view.clone())?;
        ensure(
            rotated.work.parser_epoch_rotated
                && rotated.work.tokenizations > 0
                && rotated.work.discarded_tokenizations == 0
                && rotated.work.program.reused_parse_files == 0
                && rotated.generation.canonical_artifacts() == &expected,
            "known cold demand rotates and recharges the parser with exact outputs",
        )?;
        run.checked(
            "parser_rotation",
            &json!({
                "calibrated_bytes":demand,"tokenizations":rotated.work.tokenizations,
            }),
        )?;
    }
    session.close()?;
    Ok(())
}

fn limits_and_ownership(
    campaign: Campaign,
    fixture: &Fixture,
    run: &mut Endurance<'_>,
) -> Result<()> {
    let mut limited = options(campaign);
    limited.limits.max_accounted_bytes = 1;
    let refused = Session::open(&fixture.root, &fixture.storage, limited);
    ensure(
        matches!(refused, Err(ref e) if e.kind() == SessionErrorKind::ResourceLimit),
        "tiny resident allocation account refuses admission",
    )?;
    run.checked(
        "memory_admission",
        &json!({"condition":"one_byte_account","error":"RESOURCE_LIMIT"}),
    )?;
    let mut limited = options(campaign);
    limited.limits.max_generations = 1;
    let mut session = Session::open(&fixture.root, &fixture.storage, limited)?;
    let pin = session.acquire_generation()?;
    let original = pin
        .source_view()
        .bytes(SOURCE)
        .ok_or_else(|| failure("fixture source absent"))?;
    let result = session.evaluate_delta(
        "extra",
        pin.input_revision(),
        vec![ChangeOperation::Replace {
            path: SOURCE.into(),
            base_bytes: original.to_vec(),
            candidate_bytes: [original, b"\n// Generation admission probe\n"].concat(),
        }],
    );
    ensure(
        matches!(result, Err(ref e) if e.kind() == SessionErrorKind::ResourceLimit)
            && session.acquire_generation()?.generation_id() == pin.generation_id(),
        "extra generation cannot evict a reader",
    )?;
    drop(pin);
    drop(result);
    session.close()?;
    run.checked(
        "memory_admission",
        &json!({"condition":"pinned_generation","error":"RESOURCE_LIMIT"}),
    )?;

    let runtime = RuntimeStorage::new(
        &fixture.root,
        &fixture.storage,
        options(campaign).storage_policy,
    )?;
    for _ in 0..2 {
        let workspace = runtime.acquire_workspace()?;
        ensure(
            runtime.acquire_workspace().is_err(),
            "overlapping owned writer refused",
        )?;
        workspace.release()?;
        runtime.acquire_workspace()?.release()?;
        run.checked(
            "storage_ownership",
            &json!({"exclusive_lease":true,"reacquired":true}),
        )?;
    }
    Ok(())
}

fn recovery(run: &mut Endurance<'_>) -> Result<()> {
    let executable = env::current_exe()?;
    let executable = executable
        .to_str()
        .ok_or_else(|| failure("non-Unicode executable path"))?;
    for number in 0..2 {
        let folder = run.retention.root.join(format!("recovery-{number}"));
        fs::create_dir(&folder)?;
        fs::create_dir(folder.join("repository"))?;
        fs::create_dir(folder.join("storage"))?;
        let path = folder
            .to_str()
            .ok_or_else(|| failure("non-Unicode recovery path"))?;
        let output = captured_collector(
            executable,
            &["--owned-recovery-child".into(), path.into()],
            run.retention,
        )?;
        let staging = PathBuf::from(String::from_utf8(output)?.trim());
        let (repository, storage) = recovery_paths(&folder)?;
        ensure(
            staging.starts_with(&storage) && staging.join("interrupted").is_file(),
            "owned durable crash residue",
        )?;
        let runtime = RuntimeStorage::new(&repository, &storage, StoragePolicy::default())?;
        let results = runtime.recover_owned_orphans()?;
        ensure(
            results.len() == 1 && results[0].1 == "RECOVERED" && !staging.exists(),
            "recovery removes only confirmed owned staging",
        )?;
        runtime.acquire_workspace()?.release()?;
        run.checked(
            "storage_recovery",
            &json!({"result":"RECOVERED","journal":results[0].0,"reacquired":true}),
        )?;
    }
    Ok(())
}

fn recovery_paths(folder: &Path) -> Result<(PathBuf, PathBuf)> {
    let expected = env::temp_dir()
        .join("fortress-qualification/session-benchmark")
        .canonicalize()?;
    let canonical = folder.canonicalize()?;
    let relative = canonical.strip_prefix(expected)?;
    let parts: Vec<_> = relative.iter().filter_map(|value| value.to_str()).collect();
    ensure(
        parts.len() == 2
            && parts[0].len() == 32
            && parts[0].bytes().all(|c| c.is_ascii_hexdigit())
            && matches!(parts[1], "recovery-0" | "recovery-1"),
        "qualified disposable recovery location",
    )?;
    let repository = canonical.join("repository");
    let storage = canonical.join("storage");
    ensure(
        repository.canonicalize()? == repository && storage.canonicalize()? == storage,
        "unredirected recovery paths",
    )?;
    Ok((repository, storage))
}

pub(super) fn recovery_child(folder: &Path) -> Result<()> {
    let (repository, storage) = recovery_paths(folder)?;
    ensure(
        fs::read_dir(&repository)?.next().is_none() && fs::read_dir(&storage)?.next().is_none(),
        "fresh exclusive recovery fixture",
    )?;
    let runtime = RuntimeStorage::new(&repository, &storage, StoragePolicy::default())?;
    let mut workspace = runtime.acquire_workspace()?;
    let staging = workspace.staging();
    fs::write(staging.join("interrupted"), b"owned recovery fixture")?;
    workspace.validating()?;
    workspace.publish("synthetic-endurance-recovery")?;
    println!("{}", staging.display());
    // Reproduce process loss only in the bounded disposable child. Parent recovery
    // uses retained owner markers and the actual released OS lease.
    std::process::exit(0);
}

pub(super) fn run(
    root: &Path,
    retention: &mut Retention,
    campaign: Campaign,
    selection: &Selection,
) -> Result<()> {
    let started = Instant::now();
    let fixture = Fixture::new(&retention.root, 32, false, true)?;
    let mut run = Endurance {
        retention,
        counts: BTreeMap::new(),
    };
    let mut session = Session::open(&fixture.root, &fixture.storage, options(campaign))?;
    compare_lifecycles(&mut session, &fixture, &mut run)?;
    exercise_preparation(&mut session, &mut run)?;
    let cleanup = session.close()?;
    ensure(
        cleanup.lifecycle == "CLEANUP_COMPLETE" && cleanup.retained_bytes == 0,
        "session close cleans owned staging",
    )?;
    drop(session);
    rotate_parser(campaign, &fixture, &mut run)?;
    limits_and_ownership(campaign, &fixture, &mut run)?;
    recovery(&mut run)?;
    ensure(
        run.counts == selection.lifecycle_operations,
        "complete registered lifecycle population",
    )?;
    run.retention.raw.sync_all()?;
    run.retention.events.sync_all()?;
    run.retention.check_cancellation()?;
    run.retention.document("report.json", &json!({
        "campaign":campaign.name(),"comparison_result":"NOT_APPLICABLE","lifecycle_result":"PASS",
        "successful_operations":run.counts.values().sum::<usize>(),"operation_counts":run.counts,
        "semantic_comparisons":0,"authoritative_certification":false,
        "raw_records_digest":super::file_digest(&run.retention.root.join("samples.jsonl"))?,
        "observed_root":root,"wall_time_ns":elapsed(started)?,
        "diagnostic_collectors":run.retention.collector_summary()
    }))
}
