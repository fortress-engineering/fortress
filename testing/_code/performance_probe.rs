//! Explicit prebuilt diagnostic observer; no timings are certification gates.
use fortress_core::audit::compile_repository_psm;
use fortress_core::candidate::{CandidateRequest, CandidateWorkspace};
use fortress_core::control_layout::{ControlLayout, ControlRole};
use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::migration_governance::{MigrationEvaluator, MigrationOperation};
use fortress_core::portable::digest;
use fortress_core::query::{QueryLoadOptions, QueryRequest, load_repository_query};
use fortress_core::session::{Generation, Session, SessionOptions, SourceDelta};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn elapsed(start: Instant) -> Result<u64> {
    u64::try_from(start.elapsed().as_nanos())
        .ok()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or_else(|| io::Error::other("RESOURCE_LIMIT: exact public duration range").into())
}
fn members(generation: &Generation) -> BTreeMap<String, String> {
    generation
        .canonical_artifacts()
        .iter()
        .map(|(name, bytes)| (name.clone(), digest(bytes.as_bytes())))
        .collect()
}
fn queries(root: &Path) -> Result<Value> {
    let started = Instant::now();
    let service = load_repository_query(root, &QueryLoadOptions::default())?;
    let loading = elapsed(started)?;
    let cancelled = AtomicBool::new(false);
    let inventory=service.execute(&QueryRequest::from_json_str(&json!({"protocol_version":5,"request_id":"inventory","method":"query","state_ref":service.state_ref(),"context_ref":service.context_ref(),"parameters":{"kind":"modules","page":{"limit":1}}}).to_string())?,&cancelled);
    let inventory = serde_json::to_value(inventory)?;
    let selector = inventory["result"]["data"]["records"][0]["id"]
        .as_str()
        .unwrap_or("UNAVAILABLE");
    let mut groups = Vec::new();
    for method in ["status", "doctor", "explain"] {
        let mut samples = Vec::new();
        let mut first = None;
        let mut state = String::new();
        let mut failure = None;
        for number in 0..100 {
            let started = Instant::now();
            let request=QueryRequest::from_json_str(&json!({"protocol_version":5,"request_id":format!("{method}_{number}"),"method":method,"state_ref":service.state_ref(),"context_ref":service.context_ref(),"parameters":if method=="explain" {json!({"selector":selector})} else {json!({})}}).to_string())?;
            let response = service.execute(&request, &cancelled);
            let bytes = serde_json::to_vec(&response)?;
            samples.push(elapsed(started)?);
            state.clone_from(&response.operational_state);
            failure = response.error.as_ref().map(|e| e.code.clone());
            let mut normalized: Value = serde_json::from_slice(&bytes)?;
            normalized["request_id"] = Value::Null;
            let identity = digest(&serde_json::to_vec(&normalized)?);
            if first.as_ref().is_some_and(|previous| previous != &identity) {
                return Err(io::Error::other("immutable query result changed").into());
            }
            first = Some(identity);
        }
        groups.push(json!({"method":method,"samples_ns":samples,"response_digest":first,"operational_state":state,"error_code":failure,"scope":"strict request encoding/decoding, loaded facade execution and complete response serialization; comparison hashing separate"}));
    }
    Ok(
        json!({"cold_loading_ns":loading,"explanation_selector":selector,"inventory_error":inventory["error"],"requests_per_method":100,"methods":groups,"analysis_in_query_loop":"NOT_INVOKED"}),
    )
}
fn psm(root: &Path) -> Result<Value> {
    let started = Instant::now();
    let model = compile_repository_psm(root)?;
    let construction = elapsed(started)?;
    let started = Instant::now();
    let model_digest = model.digest()?;
    let hashing = elapsed(started)?;
    Ok(
        json!({"format":"source-bound-performance-observation-v1","scope":"PSM_ONLY_UNGOVERNED_ANALYSIS","construction_ns":construction,"canonical_digest_ns":hashing,"psm_digest":model_digest,"psm_source_identity":model.source_identity(),"context_ref":model.program_context().digest(),"coverage":model.coverage(),"actual_certification":"NOT_ISSUED","execution":"NOT_RUN","authenticity":"UNVERIFIED"}),
    )
}
fn resident(root: &Path, storage: &Path, accounted: usize, repetitions: usize) -> Result<Value> {
    let query = queries(root)?;
    let mut options = SessionOptions::default();
    options.limits.max_accounted_bytes = accounted;
    let started = Instant::now();
    let mut session = Session::open(root, storage, options.clone())?;
    let startup = elapsed(started)?;
    let head = session.acquire_generation()?;
    let original = members(&head);
    let view = head.source_view().clone();
    let source = head.input_revision().to_owned();
    let context_ref = head.context_digest().to_owned();
    let authority_ref = head.authority_digest().to_owned();
    drop(head);
    let mut warm = Vec::new();
    for _ in 0..repetitions {
        let started = Instant::now();
        let update = session.refresh(&SourceDelta::default())?;
        let duration = elapsed(started)?;
        if members(&update.generation) != original {
            return Err(io::Error::other("prepared result changed").into());
        }
        warm.push(json!({"wall_time_ns":duration,"disposition":format!("{:?}",update.disposition),"fallback_reasons":update.reasons,"phases":update.work.phase_measurements}));
    }
    let started = Instant::now();
    let cold = session.evaluate_view_cold(view)?;
    let cold_time = elapsed(started)?;
    if members(&cold.generation) != original
        || cold.work.program.reused_bodies != 0
        || cold.work.semantic.reused_domain_rounds != 0
        || cold.work.state_effect.reused_direct_units != 0
    {
        return Err(io::Error::other("independent cold mismatch or owner reuse").into());
    }
    let phases = cold.work.phase_measurements.clone();
    drop(cold);
    session.evict_preparation()?;
    let started = Instant::now();
    let fallback = session.refresh(&SourceDelta::default())?;
    let fallback_time = elapsed(started)?;
    if members(&fallback.generation) != original {
        return Err(io::Error::other("eviction changed canonical result").into());
    }
    drop(fallback);
    let started = Instant::now();
    session.cancel();
    let cancelled = session.refresh(&SourceDelta::default()).unwrap_err();
    let cancellation_time = elapsed(started)?;
    if cancelled.kind() != fortress_core::session::SessionErrorKind::Cancelled {
        return Err(io::Error::other("cancellation was not explicit").into());
    }
    let retained = session.resource_usage()?;
    let cleanup = session.close()?;
    drop(session);
    let candidate = candidate_observations(root, storage, options)?;
    Ok(
        json!({"format":"source-bound-performance-observation-v1","scope":"GOVERNED_RESIDENT_AND_CANDIDATE","source_domain":"SOURCE_VIEW_IDENTITY","source_view_ref":source,"context_ref":context_ref,"authority_ref":authority_ref,"canonical_members":original,"query":query,"startup_ns":startup,"warm_evaluations":warm,"independent_cold_ns":cold_time,"independent_cold_phases":phases,"evicted_fallback_ns":fallback_time,"cancellation_ns":cancellation_time,"cancellation":"CANCELLED","resident_accounted_limit":accounted,"retained_accounting":retained,"accounting_is_not_process_rss":true,"cleanup":format!("{:?}",cleanup),"candidate":candidate,"actual_certification":"NOT_ISSUED","execution":"NOT_RUN","authenticity":"UNVERIFIED"}),
    )
}

fn candidate_operations(
    actual: &fortress_core::observation::SourceView,
) -> Result<Vec<(&'static str, MigrationOperation)>> {
    let mut operations = Vec::new();
    if let Some((path, bytes)) = actual.files().iter().find(|(path, _)| {
        Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    }) {
        let mut postimage = bytes.clone();
        postimage.extend_from_slice(b"\n// hypothetical diagnostic observation\n");
        operations.push((
            "single_file",
            MigrationOperation::ReplaceFile {
                path: path.clone(),
                preimage: bytes.clone(),
                postimage,
            },
        ));
    }
    if let Some(path) = ControlLayout::standard().role_path(ControlRole::ProjectConfiguration)
        && let Some(bytes) = actual.bytes(path)
    {
        let mut configuration: Value =
            fortress_core::wire::parse_strict_json(std::str::from_utf8(bytes)?)?;
        let catalog: Value = fortress_core::wire::parse_strict_json(
            fortress_core::profile::installed_profiles_source(),
        )?;
        let selected = catalog["profiles"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row["id"] == "ASSURE-SEMANTIC-EVALUABILITY")
            })
            .ok_or_else(|| io::Error::other("installed assurance profile absent"))?;
        let reference =
            json!({"id":selected["id"],"version":selected["version"],"digest":selected["digest"]});
        let profiles = configuration["assurance_profiles"]
            .as_array_mut()
            .ok_or_else(|| io::Error::other("assurance selection unavailable"))?;
        if !profiles.contains(&reference) {
            profiles.push(reference);
            operations.push((
                "authority_selection",
                MigrationOperation::ReplaceFile {
                    path: path.into(),
                    preimage: bytes.to_vec(),
                    postimage: serde_json::to_vec_pretty(&configuration)?,
                },
            ));
        }
    }
    Ok(operations)
}

fn candidate_observations(root: &Path, storage: &Path, options: SessionOptions) -> Result<Value> {
    let started = Instant::now();
    let mut candidates = CandidateWorkspace::open(root, storage, options)?;
    let candidate_startup = elapsed(started)?;
    let actual = fortress_core::migration_adapter::CanonicalMigrationEvaluator.observe(root)?;
    let authority = CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let operations = candidate_operations(&actual)?;
    let mut assessments = Vec::new();
    for (name, operation) in operations {
        let request = CandidateRequest {
            schema_version: 1,
            base_source_ref: candidates.base_source_ref().into(),
            context_ref: candidates.context_ref().into(),
            operations: vec![operation],
            comparison_context: fortress_core::state_governance::ComparisonContext::default(),
        };
        let started = Instant::now();
        let fast = candidates.evaluate(
            "performance_observer",
            name,
            request.clone(),
            &authority,
            &AtomicBool::new(false),
        );
        let warm_time = elapsed(started)?;
        let started = Instant::now();
        let mut independent = CandidateWorkspace::open_cold(root)?;
        let cold_startup = elapsed(started)?;
        let started = Instant::now();
        let slow = independent.evaluate(
            "performance_observer",
            name,
            request,
            &authority,
            &AtomicBool::new(false),
        );
        let cold_time = elapsed(started)?;
        let row = match (fast, slow) {
            (Ok(fast), Ok(slow)) => {
                if fast.evaluation_ref() != slow.evaluation_ref() {
                    return Err(io::Error::other("actual candidate API mismatch").into());
                }
                json!({"case":name,"prepared_ns":warm_time,"independent_startup_ns":cold_startup,"cold_ns":cold_time,"canonical_equal":true,"evaluation_ref":fast.evaluation_ref(),"evaluation_mode":fast.evaluation_mode(),"actual_state":false})
            }
            (Err(fast), Err(slow)) if fast.code == slow.code => {
                json!({"case":name,"prepared_ns":warm_time,"independent_startup_ns":cold_startup,"cold_ns":cold_time,"error_code":fast.code,"error_code_equal":true,"canonical_equal":null,"actual_state":false})
            }
            _ => return Err(io::Error::other("candidate success/error outcomes differ").into()),
        };
        assessments.push(row);
        candidates.release("performance_observer", name);
    }
    if fortress_core::migration_adapter::CanonicalMigrationEvaluator.observe(root)? != actual {
        return Err(io::Error::other("source drift during read-only observation").into());
    }
    Ok(json!({"startup_ns":candidate_startup,"assessments":assessments}))
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err(io::Error::other(
            "expected ROOT STORAGE REPORT psm|resident ACCOUNTED_BYTES WARM_EVALUATIONS",
        )
        .into());
    }
    let root = Path::new(&args[0]);
    let storage = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    let accounted = args[4].parse::<usize>()?;
    let repetitions = args[5].parse::<usize>()?;
    if repetitions > 10 || accounted == 0 || u64::try_from(accounted)? > 64 * 1024 * 1024 * 1024 {
        return Err(io::Error::other("RESOURCE_LIMIT: diagnostic options").into());
    }
    let parent = output
        .parent()
        .ok_or_else(|| io::Error::other("report parent unavailable"))?;
    if parent.canonicalize()?.starts_with(root.canonicalize()?) {
        return Err(io::Error::other("report must remain outside source").into());
    }
    let result = match args[3].as_str() {
        "psm" => psm(root)?,
        "resident" => resident(root, storage, accounted, repetitions)?,
        _ => return Err(io::Error::other("unsupported observation scope").into()),
    };
    let bytes = serde_json::to_vec_pretty(&result)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(io::Error::other("RESOURCE_LIMIT: observation bytes").into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "{}",
        json!({"observation_digest":digest(&bytes),"bytes":bytes.len(),"numeric_certification":false})
    );
    Ok(())
}
