//! Read-only baseline and exception proposals; no file write or approval deserializer.
use fortress_core::finding_governance::{ExceptionReviewPolicy, lifecycle_bytes};
use fortress_core::lifecycle_load::{
    GovernanceProposal, current_context, load_finding_authority, propose_baseline,
    propose_exception, propose_exception_retirement, propose_prune,
};
use fortress_core::state_governance::{ComparisonContext, TransitionError, assess_retirements};
use fortress_core::transition_load::load_comparison_state;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::PathBuf;
struct Options {
    operation: String,
    positionals: Vec<String>,
    values: BTreeMap<String, String>,
    findings: BTreeSet<String>,
    json: bool,
}
fn fail(code: &str, message: impl Into<String>) -> TransitionError {
    TransitionError {
        code: code.into(),
        message: message.into(),
    }
}
fn parse(args: &[String]) -> Result<Options, TransitionError> {
    let mut result = Options {
        operation: args
            .first()
            .ok_or_else(|| fail("INVALID_INPUT", "baseline/exception operation is required"))?
            .clone(),
        positionals: vec![],
        values: BTreeMap::new(),
        findings: BTreeSet::new(),
        json: false,
    };
    let allowed = [
        "--from",
        "--to",
        "--format",
        "--finding",
        "--authority",
        "--rationale",
        "--review-at",
        "--expires-at",
        "--assessment-time",
    ];
    let mut i = 1;
    while i < args.len() {
        let key = &args[i];
        if key.starts_with('-') {
            if key == "--apply" {
                return Err(fail(
                    "AUTHORIZATION_REQUIRED",
                    "the installed CLI is preview-only; an exact protected AUTHORITY decision through a trusted write-mediating host is required",
                ));
            }
            if !allowed.contains(&key.as_str()) {
                return Err(fail(
                    "INVALID_INPUT",
                    format!("unsupported lifecycle option {key}"),
                ));
            }
            i += 1;
            let value = args
                .get(i)
                .ok_or_else(|| fail("INVALID_INPUT", format!("missing value for {key}")))?;
            if value.len() > 4096 || value.starts_with("--") {
                return Err(fail("INVALID_INPUT", "empty or oversized option value"));
            }
            if key == "--finding" {
                if !result.findings.insert(value.clone()) || result.findings.len() > 50_000 {
                    return Err(fail(
                        "IDENTITY_AMBIGUOUS",
                        "duplicate or oversized finding selectors",
                    ));
                }
            } else if result.values.insert(key.clone(), value.clone()).is_some() {
                return Err(fail(
                    "INVALID_INPUT",
                    format!("duplicate lifecycle option {key}"),
                ));
            }
        } else {
            result.positionals.push(key.clone());
        }
        i += 1;
    }
    if let Some(format) = result.values.get("--format") {
        match format.as_str() {
            "json" => result.json = true,
            "human" => {}
            _ => return Err(fail("INVALID_INPUT", "format must be human or json")),
        }
    }
    Ok(result)
}
fn time(o: &Options, key: &str) -> Result<Option<u64>, TransitionError> {
    o.values
        .get(key)
        .map(|s| {
            s.parse::<u64>()
                .ok()
                .filter(|v| *v <= 9_007_199_254_740_991)
                .ok_or_else(|| {
                    fail(
                        "INVALID_INPUT",
                        format!("{key} requires an exact nonnegative public integer"),
                    )
                })
        })
        .transpose()
}
fn root(o: &Options, skip: usize) -> Result<PathBuf, TransitionError> {
    if o.positionals.len() > skip + 1 {
        return Err(fail(
            "INVALID_INPUT",
            "only one repository path is accepted",
        ));
    }
    PathBuf::from(o.positionals.get(skip).map_or(".", String::as_str))
        .canonicalize()
        .map_err(|e| fail("INVALID_INPUT", e.to_string()))
}
fn required<'a>(o: &'a Options, key: &str) -> Result<&'a str, TransitionError> {
    o.values.get(key).map(String::as_str).ok_or_else(|| {
        fail(
            "INVALID_INPUT",
            format!("required lifecycle option {key} is missing"),
        )
    })
}
fn print_json(
    output: &mut impl Write,
    value: &impl serde::Serialize,
) -> Result<(), TransitionError> {
    output
        .write_all(&lifecycle_bytes(value).map_err(|e| fail("RESOURCE_LIMIT", e.to_string()))?)
        .map_err(|e| fail("UNAVAILABLE", e.to_string()))?;
    writeln!(output).map_err(|e| fail("UNAVAILABLE", e.to_string()))
}
fn print_proposal(
    output: &mut impl Write,
    p: &GovernanceProposal,
    json: bool,
) -> Result<(), TransitionError> {
    if json {
        output
            .write_all(&p.to_canonical_bytes()?)
            .map_err(|e| fail("UNAVAILABLE", e.to_string()))?;
        writeln!(output).map_err(|e| fail("UNAVAILABLE", e.to_string()))
    } else {
        writeln!(output, "{}proposal ref: {}", p.to_human(), p.digest()?)
            .map_err(|e| fail("UNAVAILABLE", e.to_string()))
    }
}
fn baseline_execute(args: &[String], output: &mut impl Write) -> Result<(), TransitionError> {
    let o = parse(args)?;
    let root = root(&o, 0)?;
    match o.operation.as_str() {
        "capture" => {
            reject_unused(&o, &[])?;
            let (state, _) = fortress_core::audit::capture_finding_inputs(&root)
                .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
            output
                .write_all(&state.to_canonical_bytes()?)
                .map_err(|e| fail("UNAVAILABLE", e.to_string()))?;
            writeln!(output).map_err(|e| fail("UNAVAILABLE", e.to_string()))
        }
        "create" => {
            reject_unused(&o, &[])?;
            let authority = load_finding_authority(&root)?;
            let captured = fortress_core::audit::capture_finding_adoption(&root)
                .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
            let p = propose_baseline(
                &authority,
                &captured.state,
                &captured.findings,
                &captured.standard_id,
                &captured.standard_edition,
            )?;
            print_proposal(output, &p, o.json)
        }
        "review" | "prune" => {
            reject_unused(&o, &["--from", "--to"])?;
            if o.operation == "prune"
                && (!o.values.contains_key("--from") || !o.values.contains_key("--to"))
            {
                return Err(fail(
                    "RETIREMENT_EVIDENCE_REQUIRED",
                    "comparable subject, authority and coverage evidence requires explicit --from and --to states",
                ));
            }
            let authority = load_finding_authority(&root)?;
            let before = load_comparison_state(&root, required(&o, "--from")?)?;
            let after = load_comparison_state(&root, required(&o, "--to")?)?;
            if o.operation == "prune" {
                let p = propose_prune(&authority, &before, &after, &o.findings)?;
                return print_proposal(output, &p, o.json);
            }
            let records =
                assess_retirements(&before, &after, &authority, &ComparisonContext::default())?;
            if o.json {
                return print_json(output, &records);
            }
            for e in records {
                writeln!(
                    output,
                    "{}: {:?}\n  {}",
                    e.finding_id,
                    e.outcome,
                    e.reasons.join("; ")
                )
                .map_err(|e| fail("UNAVAILABLE", e.to_string()))?;
            }
            Ok(())
        }
        _ => Err(fail(
            "INVALID_INPUT",
            "usage: fortress baseline capture|create|review|prune [path] [--from state --to state] [--finding ID] [--format human|json]",
        )),
    }
}
fn reject_unused(o: &Options, allowed: &[&str]) -> Result<(), TransitionError> {
    if o.values
        .keys()
        .any(|k| k != "--format" && !allowed.contains(&k.as_str()))
        || (!o.findings.is_empty() && o.operation != "prune")
    {
        return Err(fail(
            "INVALID_INPUT",
            "option is not supported for this lifecycle operation",
        ));
    }
    Ok(())
}
fn exception_execute(args: &[String], output: &mut impl Write) -> Result<(), TransitionError> {
    let o = parse(args)?;
    match o.operation.as_str() {
        "list" => {
            reject_unused(&o, &[])?;
            let doc = load_finding_authority(&root(&o, 0)?)?;
            print_json(output, &doc)
        }
        "review" => {
            reject_unused(&o, &["--to", "--assessment-time"])?;
            let root = root(&o, 0)?;
            let doc = load_finding_authority(&root)?;
            let state = load_comparison_state(&root, required(&o, "--to")?)?;
            let context = current_context(&state, &doc, time(&o, "--assessment-time")?)?;
            let reviews = doc
                .review_exceptions(&context)
                .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
            if o.json {
                return print_json(output, &reviews);
            }
            for r in reviews {
                writeln!(
                    output,
                    "{} -> {}: review={}, scope={}, authorization={}, applies={}",
                    r.exception_id,
                    r.finding_id,
                    r.review_state,
                    r.scope_state,
                    r.authorization_state,
                    r.applicable
                )
                .map_err(|e| fail("UNAVAILABLE", e.to_string()))?;
            }
            Ok(())
        }
        "create" => {
            reject_unused(
                &o,
                &["--authority", "--rationale", "--review-at", "--expires-at"],
            )?;
            if o.positionals.len() < 2 {
                return Err(fail(
                    "INVALID_INPUT",
                    "exception creation requires exact exception and finding IDs",
                ));
            }
            let root = root(&o, 2)?;
            let authority = load_finding_authority(&root)?;
            let (state, findings) = fortress_core::audit::capture_finding_inputs(&root)
                .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
            let p = propose_exception(
                &authority,
                &state,
                &findings,
                &o.positionals[0],
                &o.positionals[1],
                required(&o, "--authority")?,
                required(&o, "--rationale")?,
                ExceptionReviewPolicy {
                    review_at: time(&o, "--review-at")?,
                    expires_at: time(&o, "--expires-at")?,
                },
            )?;
            print_proposal(output, &p, o.json)
        }
        "retire" => {
            reject_unused(&o, &["--rationale"])?;
            let id = o.positionals.first().ok_or_else(|| {
                fail(
                    "INVALID_INPUT",
                    "exception retirement requires an exact exception ID",
                )
            })?;
            let root = root(&o, 1)?;
            let authority = load_finding_authority(&root)?;
            let (state, _) = fortress_core::audit::capture_finding_inputs(&root)
                .map_err(|e| fail("INVALID_INPUT", e.to_string()))?;
            let p =
                propose_exception_retirement(&authority, &state, id, required(&o, "--rationale")?)?;
            print_proposal(output, &p, o.json)
        }
        _ => Err(fail(
            "INVALID_INPUT",
            "usage: fortress exceptions list|review|create|retire [exact IDs and review policy] [path] [--format human|json]",
        )),
    }
}
fn run(
    args: &[String],
    output: &mut impl Write,
    error: &mut impl Write,
    baseline: bool,
) -> io::Result<u8> {
    let result = if baseline {
        baseline_execute(args, output)
    } else {
        exception_execute(args, output)
    };
    match result {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(e) => {
            let exit = if matches!(
                e.code.as_str(),
                "RETIREMENT_EVIDENCE_REQUIRED" | "AUTHORIZATION_REQUIRED"
            ) {
                crate::EXIT_VIOLATION
            } else {
                crate::EXIT_USAGE
            };
            if args
                .windows(2)
                .any(|p| p[0] == "--format" && p[1] == "json")
            {
                writeln!(
                    error,
                    "{}",
                    serde_json::json!({"error":{"code":e.code,"message":e.message},"mutated":false,"authorization":"NOT_GRANTED"})
                )?;
            } else {
                writeln!(error, "lifecycle proposal failed: {e}")?;
            }
            Ok(exit)
        }
    }
}
pub(super) fn baseline<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run(args, output, error, true)
}
pub(super) fn exceptions<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    run(args, output, error, false)
}
