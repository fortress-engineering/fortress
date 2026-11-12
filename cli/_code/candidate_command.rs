//! Thin explicit read-only candidate evaluation and reconciliation commands.
use fortress_core::candidate::{
    CandidateRequest, CandidateWorkspace, HypotheticalEvaluation, inspect_post_write,
};
use fortress_core::development_governance::{
    AuthorizationRule, NoGrantValidator, TrustedBasePolicy, UnmediatedHost,
};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::migration_governance::MigrationError;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;

fn error(message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: "INVALID_ARGUMENT".into(),
        message: message.into(),
        transaction_ref: None,
    }
}
fn convert(e: impl std::fmt::Display) -> MigrationError {
    error(e.to_string())
}
fn load(root: &Path, path: &str) -> Result<String, MigrationError> {
    let value =
        fortress_core::portable_load::load_portable_json(root, Path::new(path)).map_err(convert)?;
    serde_json::to_string(&value).map_err(convert)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewSelection {
    base_state_ref: String,
    base_authority_ref: String,
    root_policy_ref: String,
    require_assurance: bool,
    rules: Vec<AuthorizationRule>,
}

pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    errors: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(failure) => {
            writeln!(
                errors,
                "{}",
                serde_json::to_string(&failure).map_err(io::Error::other)?
            )?;
            Ok(crate::EXIT_USAGE)
        }
    }
}
struct OverlayRequest<'a> {
    mode: &'a str,
    options: BTreeMap<&'a str, &'a str>,
    export: bool,
    human: bool,
    original_states: Vec<&'a str>,
}
fn parse(args: &[String]) -> Result<OverlayRequest<'_>, MigrationError> {
    let mode = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| error("overlay requires base, evaluate, inspect or reconcile"))?;
    if !["base", "evaluate", "inspect", "reconcile"].contains(&mode) {
        return Err(error("unknown overlay mode; no apply/write method exists"));
    }
    let mut options = BTreeMap::new();
    let mut original_states = Vec::new();
    let mut export = false;
    let mut index = 1;
    while index < args.len() {
        let key = args[index].as_str();
        index += 1;
        if key == "--export" && mode == "evaluate" && !export {
            export = true;
            continue;
        }
        if ![
            "--root",
            "--request",
            "--proposal",
            "--base-selection",
            "--storage-root",
            "--client",
            "--candidate",
            "--format",
            "--original-state",
        ]
        .contains(&key)
        {
            return Err(error(format!("unknown overlay option {key}")));
        }
        let value = args
            .get(index)
            .ok_or_else(|| error(format!("{key} requires a value")))?;
        index += 1;
        if key == "--original-state" {
            if mode != "evaluate" || original_states.len() >= 16 {
                return Err(error(
                    "original state preload requires evaluate and at most sixteen references",
                ));
            }
            original_states.push(value.as_str());
            continue;
        }
        if options.insert(key, value.as_str()).is_some() {
            return Err(error(format!("duplicate {key}")));
        }
    }
    let mut allowed = vec!["--root", "--format"];
    allowed.extend(match mode {
        "evaluate" => vec![
            "--request",
            "--base-selection",
            "--storage-root",
            "--client",
            "--candidate",
        ],
        "inspect" | "reconcile" => vec!["--proposal"],
        _ => vec![],
    });
    if options.keys().any(|k| !allowed.contains(k)) {
        return Err(error("option does not apply to this overlay mode"));
    }
    let human = match options.get("--format").copied().unwrap_or("human") {
        "human" => true,
        "json" => false,
        _ => return Err(error("format must be human or json")),
    };
    Ok(OverlayRequest {
        mode,
        options,
        export,
        human,
        original_states,
    })
}
fn execute<O: Write>(args: &[String], output: &mut O) -> Result<(), MigrationError> {
    let OverlayRequest {
        mode,
        options,
        export,
        human,
        original_states,
    } = parse(args)?;
    let root = Path::new(options.get("--root").copied().unwrap_or("."))
        .canonicalize()
        .map_err(convert)?;
    let value = if matches!(mode, "inspect" | "reconcile") {
        let path = options
            .get("--proposal")
            .ok_or_else(|| error("explicit --proposal required"))?;
        let candidate = HypotheticalEvaluation::from_json_str(&load(&root, path)?)?;
        if mode == "reconcile" {
            serde_json::to_value(inspect_post_write(
                &root,
                &candidate,
                &AtomicBool::new(false),
            )?)
            .map_err(convert)?
        } else {
            serde_json::to_value(candidate).map_err(convert)?
        }
    } else {
        let mut workspace = if let Some(storage) = options.get("--storage-root") {
            CandidateWorkspace::open(
                &root,
                Path::new(storage),
                fortress_core::session::SessionOptions::default(),
            )?
        } else {
            CandidateWorkspace::open_cold(&root)?
        };
        if !original_states.is_empty() {
            let states = original_states
                .iter()
                .map(|reference| {
                    fortress_core::transition_load::load_comparison_state(&root, reference)
                        .map_err(convert)
                })
                .collect::<Result<Vec<_>, _>>()?;
            workspace = workspace.with_original_states(states)?;
        }
        if mode == "base" {
            json!({"base_source_ref":workspace.base_source_ref(),"context_ref":workspace.context_ref(),"base_state_ref":workspace.base_state().digest().map_err(convert)?,"trusted_base_authority":workspace.base_state().governing_identity().map_err(convert)?,"request_schema":"urn:fortress:derived:v1:candidate-request","request_schema_version":1,"status":"OBSERVED_BASE","permission":"NONE","actual_certification":false})
        } else {
            evaluate_proposal(&root, &mut workspace, &options, export)?
        }
    };
    if human {
        write!(
            output,
            "{}",
            fortress_core::query::render_inspection_value(&value)
        )
        .map_err(convert)?;
    } else {
        output
            .write_all(
                &fortress_core::wire::canonicalize_public_json(&value.to_string())
                    .map_err(convert)?,
            )
            .map_err(convert)?;
        writeln!(output).map_err(convert)?;
    }
    Ok(())
}

fn evaluate_proposal(
    root: &Path,
    workspace: &mut CandidateWorkspace,
    options: &BTreeMap<&str, &str>,
    export: bool,
) -> Result<serde_json::Value, MigrationError> {
    let path = options
        .get("--request")
        .ok_or_else(|| error("explicit --request required"))?;
    let request: CandidateRequest =
        fortress_core::wire::parse_public_json(&load(root, path)?).map_err(convert)?;
    let selected = if let Some(path) = options.get("--base-selection") {
        let s: PreviewSelection =
            fortress_core::wire::parse_public_json(&load(root, path)?).map_err(convert)?;
        Some(
            TrustedBasePolicy::from_host(
                s.base_state_ref,
                s.base_authority_ref,
                s.root_policy_ref,
                s.require_assurance,
                s.rules,
            )
            .map_err(convert)?,
        )
    } else {
        None
    };
    let authority = CanonicalMigrationAuthority {
        policy: selected.as_ref(),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let candidate = workspace.evaluate(
        options.get("--client").copied().unwrap_or("cli"),
        options.get("--candidate").copied().unwrap_or("proposal"),
        request,
        &authority,
        &AtomicBool::new(false),
    )?;
    let exported = if export {
        Some(candidate.export_proposal(root)?)
    } else {
        None
    };
    if let Some(path) = exported {
        Ok(json!({"proposal_path":path,"assessment":candidate}))
    } else {
        serde_json::to_value(candidate).map_err(convert)
    }
}
