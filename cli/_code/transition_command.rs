//! Read-only exact state capture and shared transition query adapter.
use fortress_core::query::{QueryLoadOptions, QueryRequest, load_repository_query};
use fortress_core::state_governance::ComparisonContext;
use fortress_core::transition_load::load_comparison_state;
use serde_json::json;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(code) => Ok(code),
        Err(message) => {
            writeln!(error, "transition failed: {message}")?;
            Ok(crate::EXIT_USAGE)
        }
    }
}
fn execute<O: Write>(args: &[String], output: &mut O) -> Result<u8, String> {
    let mut from = None;
    let mut to = None;
    let mut root = PathBuf::from(".");
    let mut json_output = false;
    let mut capture = false;
    let mut context = ComparisonContext::default();
    let mut page = json!({});
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    let mut path_seen = false;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') && !seen.insert(arg) {
            return Err(format!("duplicate option {arg}"));
        }
        match arg.as_str() {
            "capture" if i == 0 => capture = true,
            "--from" | "--to" | "--format" | "--limit" | "--cursor" | "--context" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                match arg.as_str() {
                    "--from" => from = Some(value.clone()),
                    "--to" => to = Some(value.clone()),
                    "--format" => match value.as_str() {
                        "json" => json_output = true,
                        "human" => {}
                        _ => return Err("format must be human or json".into()),
                    },
                    "--limit" => {
                        page["limit"] = json!(
                            value
                                .parse::<usize>()
                                .map_err(|_| "limit requires an unsigned integer")?
                        );
                    }
                    "--cursor" => page["cursor"] = json!(value),
                    "--context" => {
                        context = fortress_core::transition_load::load_comparison_context(
                            std::path::Path::new(value),
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    _ => unreachable!(),
                }
            }
            x if x.starts_with('-') => return Err(format!("unsupported transition option {x}")),
            _ => {
                if path_seen {
                    return Err("only one repository path is accepted".into());
                }
                path_seen = true;
                root = PathBuf::from(arg);
            }
        }
        i += 1;
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    if capture {
        if from.is_some()
            || to.is_some()
            || !page.as_object().unwrap().is_empty()
            || !context.counterfactuals.is_empty()
            || !context.authorization_refs.is_empty()
        {
            return Err("capture does not accept comparison options".into());
        }
        let state = load_comparison_state(&root, "current").map_err(|e| e.to_string())?;
        output
            .write_all(&state.to_canonical_bytes().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        writeln!(output).map_err(|e| e.to_string())?;
        return Ok(crate::EXIT_SUCCESS);
    }
    let from = load_comparison_state(&root, &from.ok_or("explicit --from is required")?)
        .map_err(|e| e.to_string())?;
    let to = load_comparison_state(&root, &to.ok_or("explicit --to is required")?)
        .map_err(|e| e.to_string())?;
    let from_ref = from.digest().map_err(|e| e.to_string())?;
    let to_ref = to.digest().map_err(|e| e.to_string())?;
    let service = load_repository_query(&root, &QueryLoadOptions::default())
        .map_err(|e| e.to_string())?
        .with_comparison_states(vec![from, to])
        .map_err(|e| e.to_string())?;
    let response=service.execute(&QueryRequest{protocol_version:2,request_id:"cli".into(),method:"transition".into(),state_ref:None,context_ref:None,parameters:json!({"from_state_ref":from_ref,"to_state_ref":to_ref,"comparison_context":context,"page":page})},&AtomicBool::new(false));
    if json_output {
        output
            .write_all(&response.to_canonical_bytes().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        writeln!(output).map_err(|e| e.to_string())?;
    } else {
        write!(output, "{}", response.to_human()).map_err(|e| e.to_string())?;
    }
    Ok(if response.error.is_some() {
        crate::EXIT_USAGE
    } else {
        crate::EXIT_SUCCESS
    })
}
