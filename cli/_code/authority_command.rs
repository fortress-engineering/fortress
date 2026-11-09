//! Preview-only adapter; repository files never supply a grant validator.
use fortress_core::authority_load::{
    AuthoritySnapshot, capture_authority_snapshot, prepare_authority_change,
    preview_authority_change,
};
use fortress_core::development_governance::{AuthorizationRule, TrustedBasePolicy};
use fortress_core::state_governance::ComparisonContext;
use serde::Deserialize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
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
    error: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(e) => {
            writeln!(error, "authority preview failed: {e}")?;
            Ok(crate::EXIT_USAGE)
        }
    }
}
fn execute<O: Write>(args: &[String], output: &mut O) -> Result<(), String> {
    let mode = args
        .first()
        .ok_or("authority requires capture, preview or inspect")?;
    if mode == "capture" {
        if args.len() > 2 {
            return Err("capture accepts one repository path".into());
        }
        let root = PathBuf::from(args.get(1).map_or(".", String::as_str))
            .canonicalize()
            .map_err(message)?;
        let snapshot = capture_authority_snapshot(&root).map_err(message)?;
        output
            .write_all(&snapshot.to_canonical_bytes().map_err(message)?)
            .map_err(message)?;
        writeln!(output).map_err(message)?;
        return Ok(());
    }
    let mut from = None;
    let mut to = None;
    let mut policy = None;
    let mut decision = None;
    let mut human = true;
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 1;
    while i < args.len() {
        let key = &args[i];
        if !seen.insert(key) {
            return Err(format!("duplicate option {key}"));
        }
        i += 1;
        let value = args
            .get(i)
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key.as_str() {
            "--from" => from = Some(value),
            "--to" => to = Some(value),
            "--base-selection" => policy = Some(value),
            "--decision" => decision = Some(value),
            "--format" => match value.as_str() {
                "human" => human = true,
                "json" => human = false,
                _ => return Err("format must be human or json".into()),
            },
            _ => return Err(format!("unknown option {key}")),
        }
        i += 1;
    }
    let result = match mode.as_str() {
        "preview" => {
            if decision.is_some() {
                return Err("preview does not accept a decision receipt".into());
            }
            let a =
                AuthoritySnapshot::from_json_str(&read(from.ok_or("explicit --from required")?)?)
                    .map_err(message)?;
            let b = AuthoritySnapshot::from_json_str(&read(to.ok_or("explicit --to required")?)?)
                .map_err(message)?;
            let selected:PreviewSelection=fortress_core::wire::parse_public_json(&read(policy.ok_or("explicit --base-selection required; no public protected-authority default is inferred")?)?).map_err(message)?;
            let policy = TrustedBasePolicy::from_host(
                selected.base_state_ref,
                selected.base_authority_ref,
                selected.root_policy_ref,
                selected.require_assurance,
                selected.rules,
            )
            .map_err(message)?;
            let prepared =
                prepare_authority_change(&a, &b, &ComparisonContext::default()).map_err(message)?;
            preview_authority_change(&prepared, &policy).map_err(message)?
        }
        "inspect" => {
            if from.is_some() || to.is_some() || policy.is_some() {
                return Err("inspect accepts only --decision and --format".into());
            }
            fortress_core::development_governance::ChangeDecision::from_json_str(&read(
                decision.ok_or("explicit --decision required")?,
            )?)
            .map_err(message)?
        }
        _ => return Err("authority requires capture, preview or inspect".into()),
    };
    if human {
        write!(output, "{}", result.to_human()).map_err(message)?;
    } else {
        output
            .write_all(&result.to_canonical_bytes().map_err(message)?)
            .map_err(message)?;
        writeln!(output).map_err(message)?;
    }
    Ok(())
}
fn read(path: &str) -> Result<String, String> {
    let root = std::env::current_dir().map_err(message)?;
    let value = fortress_core::portable_load::load_portable_json(&root, Path::new(path))
        .map_err(message)?;
    serde_json::to_string(&value).map_err(message)
}
fn message(e: impl std::fmt::Display) -> String {
    e.to_string()
}
